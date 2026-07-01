package handler

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
	"unicode"

	i18n "leblanc.io/open-go-base/i18n"

	"open-go-dig/internal/dns"
	"open-go-dig/internal/model"
	"open-go-dig/internal/query"
)

// ─── App holds the application state ──────────────────────────────────────────

type App struct {
	DNSClient  *dns.Client
	Logger     *slog.Logger
	I18n       *i18n.Bundle
	indexTmpl  *template.Template
	resultTmpl *template.Template
	aboutTmpl  *template.Template
	TemplateFS fs.FS
	Debug      bool
}

// ─── Input sanitization ──────────────────────────────────────────────────────

const maxInputLength = 253

// sanitize cleans the raw query input.
func sanitize(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" || len(s) > maxInputLength {
		return ""
	}
	return s
}

// sanitizeDomain cleans a domain name input.
func sanitizeDomain(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	for _, pfx := range []string{"https://", "http://"} {
		s = strings.TrimPrefix(s, pfx)
	}
	if i := strings.Index(s, "/"); i != -1 {
		s = s[:i]
	}
	if i := strings.Index(s, "?"); i != -1 {
		s = s[:i]
	}
	s = strings.TrimSuffix(s, ".")
	var b strings.Builder
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '.' || r == ':' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// parseTypePrefix extracts an optional TYPE: prefix from the query.
// Returns the extracted record types and the remaining domain.
func parseTypePrefix(input string) ([]uint16, string) {
	if i := strings.Index(input, ":"); i > 0 && i < len(input)-1 {
		prefix := strings.ToUpper(input[:i])
		// Check if the prefix is a valid record type
		types := dns.ParseRecordTypes(prefix)
		if len(types) > 0 {
			return types, input[i+1:]
		}
	}
	return nil, input
}

// ─── Main lookup logic ────────────────────────────────────────────────────────

const lookupTimeout = 30 * time.Second

func (a *App) lookup(parentCtx context.Context, raw string, typeParam string, resolverParam string, loc *i18n.Localizer) *model.DNSResult {
	ctx, cancel := context.WithTimeout(parentCtx, lookupTimeout)
	defer cancel()

	input := sanitize(raw)
	if input == "" {
		return &model.DNSResult{
			Query: raw,
			Error: loc.T("error.empty_query"),
		}
	}

	// Resolver selection: empty → default failover behavior; otherwise the
	// value MUST match one of the configured resolvers exactly. We never let
	// users supply a free-form network address — see SECURITY notes in
	// AllowedResolver.
	var resolverOverride string
	if resolverParam != "" {
		matched, ok := a.AllowedResolver(resolverParam)
		if !ok {
			return &model.DNSResult{
				Query: raw,
				Error: loc.T("error.invalid_resolver"),
			}
		}
		resolverOverride = matched
	}

	// Check for TYPE:domain prefix
	prefixTypes, domain := parseTypePrefix(input)
	domain = sanitizeDomain(domain)

	if domain == "" {
		return &model.DNSResult{
			Query: raw,
			Error: loc.T("error.invalid_input"),
		}
	}

	// Determine record types: prefix takes priority, then query param, then defaults
	var recordTypes []uint16
	if len(prefixTypes) > 0 {
		recordTypes = prefixTypes
	} else if typeParam != "" {
		recordTypes = dns.ParseRecordTypes(typeParam)
	}

	// Detect if this is a reverse DNS query
	qt := query.Detect(domain)
	isReverse := qt == query.TypeIPv4 || qt == query.TypeIPv6

	result, err := a.DNSClient.Lookup(ctx, domain, recordTypes, isReverse, resolverOverride)
	if err != nil {
		return &model.DNSResult{
			Query: domain,
			Error: fmt.Sprintf(loc.T("error.dns_failed"), err),
		}
	}

	return result
}

// normalizeResolver mirrors the normalization performed by dns.NewClient: a
// resolver string with no port gets `:53` appended. It is purely textual and
// does NOT validate that the host is reachable, public, or well-formed.
func normalizeResolver(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(s); err != nil {
		s = s + ":53"
	}
	return s
}

// AllowedResolver checks that the user-supplied resolver matches one of the
// admin-configured resolvers exactly (after `:53` normalization) and returns
// the canonical entry from the allowlist.
//
// SECURITY: this is the single gate preventing SSRF via the resolver feature.
// Accepting arbitrary user-supplied addresses would let clients probe
// internal services (loopback, RFC1918, link-local, IPv6 ULA, …) and turn
// the server into an open DNS forwarder. We therefore enforce strict
// membership in `a.DNSClient.Resolvers` — never parse the input as an IP and
// never apply private-range filtering as a substitute (IPv6 has too many
// reserved ranges to enumerate safely).
func (a *App) AllowedResolver(input string) (string, bool) {
	target := normalizeResolver(input)
	if target == "" {
		return "", false
	}
	for _, r := range a.DNSClient.Resolvers {
		if r == target {
			return r, true
		}
	}
	return "", false
}

// ─── Template helpers ─────────────────────────────────────────────────────────

func (a *App) buildFuncMap(loc *i18n.Localizer) template.FuncMap {
	fm := template.FuncMap{
		"rawHTML": func(s string) template.HTML {
			return template.HTML(s)
		},
		"lang": func() string { return loc.Lang().String() },
		"recordTypeClass": func(t string) string {
			switch strings.ToUpper(t) {
			case "A", "AAAA", "PTR":
				return "rtype-a"
			case "MX", "NS", "SRV":
				return "rtype-mx"
			case "TXT", "SOA":
				return "rtype-txt"
			case "CNAME":
				return "rtype-cname"
			case "CAA":
				return "rtype-caa"
			case "DNSKEY", "DS", "TLSA":
				return "rtype-ds"
			default:
				return "rtype-other"
			}
		},
		"isReverseDNS": func(qt model.QueryType) bool {
			return qt == model.QueryReverse
		},
		"formatTTL": func(ttl uint32) string {
			d := time.Duration(ttl) * time.Second
			if d >= 24*time.Hour {
				days := d / (24 * time.Hour)
				rem := d % (24 * time.Hour)
				if rem > 0 {
					return fmt.Sprintf("%dd%s", days, rem)
				}
				return fmt.Sprintf("%dd", days)
			}
			if d >= time.Hour {
				return fmt.Sprintf("%s", d)
			}
			if d >= time.Minute {
				return fmt.Sprintf("%s", d)
			}
			return fmt.Sprintf("%ds", ttl)
		},
		"rcodeClass": func(rcode string) string {
			switch strings.ToUpper(rcode) {
			case "NOERROR":
				return "rcode-noerror"
			case "NXDOMAIN":
				return "rcode-nxdomain"
			case "SERVFAIL":
				return "rcode-servfail"
			case "REFUSED":
				return "rcode-refused"
			default:
				return "rcode-other"
			}
		},
		"totalRecords": func(groups []model.RecordGroup) int {
			n := 0
			for _, g := range groups {
				n += len(g.Records)
			}
			return n
		},
	}
	// Merge the localizer's T / Tn helpers on top of the app-specific ones.
	for k, v := range loc.FuncMap() {
		fm[k] = v
	}
	return fm
}

func (a *App) InitTemplates() {
	fm := a.buildFuncMap(a.I18n.Localizer("", ""))
	a.indexTmpl = template.Must(
		template.New("index.html").Funcs(fm).ParseFS(a.TemplateFS, "index.html"),
	)
	a.resultTmpl = template.Must(
		template.New("result.html").Funcs(fm).ParseFS(a.TemplateFS, "result.html"),
	)
	a.aboutTmpl = template.Must(
		template.New("about.html").Funcs(fm).ParseFS(a.TemplateFS, "about.html"),
	)
}

// renderLocalized clones a parsed template, overrides the FuncMap with the
// language-specific one, and renders the result.
func (a *App) renderLocalized(w http.ResponseWriter, tmpl *template.Template, statusCode int, loc *i18n.Localizer, data any) error {
	clone, err := tmpl.Clone()
	if err != nil {
		return err
	}
	clone.Funcs(a.buildFuncMap(loc))
	var buf bytes.Buffer
	if err := clone.Execute(&buf, data); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Vary", "Accept-Language")
	if statusCode != 0 && statusCode != http.StatusOK {
		w.WriteHeader(statusCode)
	}
	if _, err := buf.WriteTo(w); err != nil {
		a.Logger.Debug("template response write failed", "err", err)
	}
	return nil
}

// localizer resolves the request language: the ?lang= query parameter takes
// priority, then the Accept-Language header, falling back to the default.
func (a *App) localizer(r *http.Request) *i18n.Localizer {
	return a.I18n.FromRequest(r)
}
