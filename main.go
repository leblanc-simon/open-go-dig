package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"leblanc.io/open-go-base/appconf"
	"leblanc.io/open-go-base/corsx"
	i18n "leblanc.io/open-go-base/i18n"
	"leblanc.io/open-go-base/logx"
	"leblanc.io/open-go-base/ratelimit"

	"open-go-dig/internal/config"
	"open-go-dig/internal/dns"
	"open-go-dig/internal/handler"
	"open-go-dig/internal/middleware"
)

// ─── Version ──────────────────────────────────────────────────────────────────

var version = "develop"

const appName = "open-go-dig"

// ─── Embedded assets ──────────────────────────────────────────────────────────

//go:embed static
var staticFiles embed.FS

//go:embed templates
var templateFiles embed.FS

//go:embed locales
var localeFiles embed.FS

// defaultLanguage is the i18n fallback (BCP 47 tag) used when a request
// prefers no available language.
const defaultLanguage = "en"

// ─── Entry point ──────────────────────────────────────────────────────────────

func main() {
	var cfg config.Config
	appconf.MustLoad(&cfg, appconf.Options{
		Name:           appName,
		Version:        version,
		DefaultCfgPath: "config.yaml",
	})

	logger := logx.New(cfg.Log)
	debug := cfg.IsDebug()

	dnsCl := dns.NewClient(cfg.DNS.Resolvers, cfg.DNS.Timeout, cfg.DNS.MaxParallel)
	dnsCl.Debug = debug

	appHandler, err := newHandler(&cfg, dnsCl, logger)
	if err != nil {
		logger.Error("build handler", "err", err)
		os.Exit(1)
	}

	host := cfg.Web.Host
	port := strconv.Itoa(cfg.Web.Port)
	addr := host + ":" + port

	srv := &http.Server{
		Addr:         addr,
		Handler:      appHandler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Graceful shutdown
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)

	go func() {
		logger.Info("starting",
			"app", appName,
			"version", version,
			"addr", addr,
			"log_level", cfg.Log.Level,
			"rate_limit", cfg.Web.RateLimit,
			"resolvers", dnsCl.Addrs(),
			"cors_origins", cfg.CORS.AllowedOrigins,
		)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server", "err", err)
			os.Exit(1)
		}
	}()

	<-done
	logger.Info("shutting down")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown", "err", err)
		os.Exit(1)
	}
	logger.Info("server stopped gracefully")
}

// newHandler builds the complete HTTP pipeline: templates, translations, rate
// limiter, routes and middlewares. It lives apart from main so the tests exercise
// the same wiring as production, the middleware order included.
func newHandler(cfg *config.Config, dnsCl *dns.Client, logger *slog.Logger) (http.Handler, error) {
	tmplFS, err := fs.Sub(templateFiles, "templates")
	if err != nil {
		return nil, fmt.Errorf("templates embed: %w", err)
	}

	// Translations are loaded from the embedded locales/ directory so the
	// binary stays self-contained (no locales/ folder to deploy alongside it).
	bundle, err := i18n.NewFS(localeFiles, "locales", defaultLanguage)
	if err != nil {
		return nil, fmt.Errorf("i18n bundle: %w", err)
	}

	a := &handler.App{
		DNSClient:  dnsCl,
		Logger:     logger,
		I18n:       bundle,
		TemplateFS: tmplFS,
		Debug:      cfg.IsDebug(),
	}
	a.InitTemplates()

	// Rate limiter: real client IP is resolved through TrustedProxies, and the
	// 429 body is a localized JSON payload.
	limiter, err := ratelimit.New(cfg.Web.RateLimit, cfg.Web.TrustedProxies,
		ratelimit.WithLimitHandler(rateLimitHandler(bundle)))
	if err != nil {
		return nil, fmt.Errorf("rate limiter: %w", err)
	}

	// Application routes are rate-limited; static assets are served from a
	// separate mux that bypasses the limiter so shared page assets do not
	// exhaust a client's budget.
	appMux := http.NewServeMux()
	appMux.HandleFunc("GET /{$}", a.IndexHandler)
	appMux.HandleFunc("GET /about", a.AboutHandler)
	appMux.HandleFunc("GET /lookup", a.LookupHandler)
	appMux.HandleFunc("GET /api/lookup", a.ApiHandler)
	appMux.HandleFunc("GET /api/status", a.StatusHandler)

	staticSub, err := fs.Sub(staticFiles, "static")
	if err != nil {
		return nil, fmt.Errorf("static embed: %w", err)
	}

	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))
	mux.Handle("/", limiter.Middleware(appMux))

	return middleware.SecurityHeaders()(
		corsx.Middleware(cfg.CORS)(
			middleware.Link()(mux),
		),
	), nil
}

// rateLimitHandler renders the 429 response as a localized JSON body. The
// Retry-After / X-RateLimit-* headers are already set by the limiter.
func rateLimitHandler(bundle *i18n.Bundle) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		loc := bundle.FromRequest(r)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusTooManyRequests)
		// %q would not do: Go escapes are not all valid JSON.
		_ = json.NewEncoder(w).Encode(map[string]string{"error": loc.T("error.rate_limit")})
	})
}
