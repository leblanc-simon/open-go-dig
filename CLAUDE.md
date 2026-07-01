# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & run

- `make debug` — build a development binary into `build/open-go-dig` (no ldflags).
- `make release` — cross-compile release binaries for linux/darwin/windows (amd64/arm64/386). Version is taken from `git describe --tags --abbrev=0`, fallback `develop`, injected via `-X main.version=...`.
- `make clean-build` — wipe `build/`.
- `go run . -c config.yaml` — run from source. With no `-c` flag the binary tries `./config.yaml`, then falls back to environment variables (prefix `OGD_`). The default port is 8080.
- `go build .` — quick local build. The binary embeds `static/`, `templates/` and `locales/` via `//go:embed` directives in `main.go`, so the built binary is fully self-contained and does not need those directories at runtime.

There is no test suite in this repo and no linter configuration; `go vet ./...` and `go build ./...` are the available correctness checks.

## Architecture

OpenGoDig is a single-binary web frontend for DNS lookups (think `dig` in a browser) plus a JSON API. **Hard architectural rules** (enforced by `docs/prompt-open-go-dig.md`, the original spec):

- Go 1.26+, **standard library only** for HTTP — no gin/echo/chi. Routing uses `http.NewServeMux` with the `"GET /path"` pattern syntax from Go 1.22+.
- Cross-cutting concerns are delegated to the shared **`leblanc.io/open-go-base`** module: `appconf` (config), `corsx` (CORS), `ratelimit` (per-IP limiter), `logx` (slog logger), `i18n` (translations). `miekg/dns` remains the DNS client. Do not re-implement these locally and do not introduce a web framework or a CSS/JS framework — the frontend is hand-rolled.
- i18n uses `base/i18n` via `i18n.NewFS` fed by an **embedded** `locales/` directory (`//go:embed locales` in `main.go`), so the binary stays self-contained — `base/i18n.New` (disk-based) is deliberately **not** used.
- Templates, static assets and locales are embedded via `embed.FS` in `main.go`; never read them from disk at runtime.

### Request pipeline

`main.go` wires the dependency graph and the middleware stack. The order matters — outermost first:

```
SecurityHeaders()          → X-Content-Type-Options / X-Frame-Options / Referrer-Policy / CSP, always
  → corsx.Middleware(CORS) → CORS negotiation from cfg.CORS; short-circuits OPTIONS preflight
    → Link()               → HTTP Link header preload hints for above-the-fold CSS/fonts
      → mux                → /static/* served directly; everything else wrapped by limiter.Middleware
```

Static assets bypass the rate limiter by being registered on the outer `mux` directly, while all other routes go through `limiter.Middleware(appMux)`. The limiter comes from `ratelimit.New(cfg.Web.RateLimit, cfg.Web.TrustedProxies, ...)`; its `ClientIP` only honours `X-Forwarded-For` / `X-Real-IP` when `r.RemoteAddr` falls inside a trusted CIDR. Deploying behind a reverse proxy without populating `OGD_TRUSTED_PROXIES` will rate-limit the proxy IP instead of real clients. The 429 body is a localized JSON payload set via `ratelimit.WithLimitHandler` (see `rateLimitHandler` in `main.go`). Default limit is 100 req/min (the `appconf.Web` default).

### DNS resolution flow

`internal/handler/handler.go` → `App.lookup` is the single entry point used by both the HTML (`lookup.go`) and JSON (`api.go`) handlers. Sequence:

1. `sanitize` (length cap 253, trim) → `parseTypePrefix` extracts `TYPE:domain` syntax (e.g. `MX:google.com`) → `sanitizeDomain` strips schemes/paths and whitelists `[a-z0-9.\-:]`.
2. `query.Detect` distinguishes domain / IPv4 / IPv6 (the latter two trigger a reverse PTR query).
3. Type resolution priority: prefix > `?type=` query param > defaults (`A,AAAA,MX,NS,TXT,CNAME,SOA,CAA`). Reverse queries always force `PTR` and ignore type hints.
4. `dns.Client.Lookup` iterates the configured resolvers (default `8.8.8.8:53, 1.1.1.1:53, 9.9.9.9:53`) using UDP, falling back to TCP per-query when the response is truncated. Per-query failures become `Warnings` rather than fatal errors so a partial result still renders.
5. Records are grouped by type in `model.RecordGroup`; group order in the response follows the order of types in the request.

A 30s lookup timeout is applied via `context.WithTimeout` in `App.lookup`, layered on top of the per-resolver `cfg.DNS.Timeout`.

### Templates and i18n

Translations live in `locales/<lang>.yaml` (go-i18n flat format: `message.id: "text"`), embedded and loaded once at startup by `i18n.NewFS(localeFiles, "locales", "en")` in `main.go` into an `*i18n.Bundle` stored on `App.I18n`. The available languages are derived dynamically from the YAML files present, so **adding a language is just dropping a `locales/xx.yaml`** — no code change.

`App.InitTemplates` parses each HTML template **once** with a default-language `FuncMap`. Per request, `App.localizer(r)` builds an `*i18n.Localizer` (language from `?lang=` then `Accept-Language`, falling back to the default), and `renderLocalized` calls `template.Clone()` and re-binds a fresh `FuncMap` for that localizer. `buildFuncMap` merges the localizer's `T`/`Tn` helpers with the app-specific ones (`rawHTML`, `lang`, `recordTypeClass`, `rcodeClass`, `formatTTL`, `totalRecords`, `isReverseDNS`). The response always sets `Vary: Accept-Language`. In templates, use `{{T "key"}}` (and `{{rawHTML (T "key")}}` for HTML values).

Template helpers (`buildFuncMap`) include `recordTypeClass`, `rcodeClass`, `formatTTL`, `totalRecords`, `isReverseDNS` — these are referenced by `templates/result.html` and the CSS in `static/css/main.css`. If you add new record types or rcodes, both the helper and the CSS need a class.

### Configuration surface

`internal/config/config.go` is the single source of truth for runtime configuration. It composes the shared `appconf` fragments (`Web`, `CORS`, `Logging`) plus an app-specific `DNS` fragment, each embedded under an `env-prefix:"OGD_"`. Fragment fields declare their env tags **without** the prefix; the prefix is applied at the composition point (cleanenv only supports a static prefix). Config is loaded by `appconf.MustLoad` in `main.go`, which also wires the `-c`, `--help` (with env-var docs) and `--version` flags — **do not** read env vars or flags ad-hoc elsewhere. Adding app-specific configuration means adding a field to the `DNS` fragment (or a new fragment) with both `yaml` and `env` tags.

Env vars follow the fragment tags: `OGD_HOST`, `OGD_PORT`, `OGD_RATE_LIMIT`, `OGD_TRUSTED_PROXIES` (from `appconf.Web`); `OGD_CORS_ALLOWED_ORIGINS`, `OGD_CORS_ALLOW_CREDENTIALS`, … (from `appconf.CORS`); `OGD_LOG_LEVEL`, `OGD_LOG_FORMAT`, `OGD_LOG_SOURCE` (from `appconf.Logging`); `OGD_DNS_RESOLVERS`, `OGD_DNS_TIMEOUT` (from the local `DNS` fragment). Run `./build/open-go-dig --help` for the full list.

## Routes

| Method | Path | Handler | Notes |
|---|---|---|---|
| GET | `/` | `IndexHandler` | search form |
| GET | `/about` | `AboutHandler` | |
| GET | `/lookup?query=...&type=...` | `LookupHandler` | HTML; reverse DNS auto-detected from IP input; supports `TYPE:domain` shortcut |
| GET | `/api/lookup?query=...&type=...` | `ApiHandler` | JSON; same lookup logic; `502` on resolver failure |
| GET | `/api/status` | `StatusHandler` | per-resolver latency probe |
| GET | `/static/*` | embedded FS | bypasses rate limit |

## Conventions

- Package layout follows the spec in `docs/prompt-open-go-dig.md` — keep `internal/{config,dns,handler,middleware,model,query}` boundaries intact. The `handler` package owns HTTP-shaped logic and template state; `dns` is transport-agnostic. (i18n now lives in `base/i18n` + `locales/`, no longer under `internal/`.)
- Error messages exposed to users go through the request's localizer (`loc.T(key)`) — do not hard-code English strings in handlers. Internal logs (structured via `slog`) stay in English.
- License is WTFPL (`COPYING`).
