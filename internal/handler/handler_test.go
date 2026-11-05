package handler

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"

	mdns "github.com/miekg/dns"
	i18n "leblanc.io/open-go-base/i18n"

	"open-go-dig/internal/dns"
	"open-go-dig/internal/dnstest"
	"open-go-dig/internal/model"
)

func newTestApp(t *testing.T, resolvers ...string) *App {
	t.Helper()
	bundle, err := i18n.NewFS(os.DirFS("../../locales"), ".", "en")
	if err != nil {
		t.Fatal(err)
	}
	a := &App{
		DNSClient:  dns.NewClient(resolvers, 1, 8),
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		I18n:       bundle,
		TemplateFS: os.DirFS("../../templates"),
	}
	a.InitTemplates()
	return a
}

func TestSanitize(t *testing.T) {
	exact := strings.Repeat("a", maxInputLength)
	tests := map[string]string{
		"":              "",
		"   ":           "",
		" example.com ": "example.com",
		exact:           exact,
		exact + "a":     "",
	}
	for input, want := range tests {
		if got := sanitize(input); got != want {
			t.Errorf("sanitize(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestSanitizeDomain(t *testing.T) {
	longLabel := strings.Repeat("a", 64) + ".example"
	tests := []struct{ input, want string }{
		// Plain names.
		{"example.com", "example.com"},
		{"  Example.COM  ", "example.com"},
		{"example.com.", "example.com"},
		{"_dmarc.example.com", "_dmarc.example.com"},
		{"_25._tcp.mail.example.com", "_25._tcp.mail.example.com"},
		{"my-host.example.com", "my-host.example.com"},
		{"xn--mnchen-3ya.de", "xn--mnchen-3ya.de"},
		{"localhost", "localhost"},

		// Pasted URLs keep only their host.
		{"http://example.com", "example.com"},
		{"https://example.com", "example.com"},
		{"HTTPS://Example.com/Page", "example.com"},
		{"https://example.com/path?x=1#frag", "example.com"},
		{"https://example.com?x=1", "example.com"},
		{"example.com/path", "example.com"},
		{"example.com#frag", "example.com"},
		{"https://example.com:8443/", "example.com"},
		{"example.com:8080", "example.com"},

		// IP addresses.
		{"1.1.1.1", "1.1.1.1"},
		{"2001:DB8::1", "2001:db8::1"},
		{"::ffff:1.2.3.4", "::ffff:1.2.3.4"},
		{"[2001:db8::1]", "2001:db8::1"},
		{"http://[2001:db8::1]:8080/path", "2001:db8::1"},

		// Internationalized names travel in their ASCII form.
		{"münchen.de", "xn--mnchen-3ya.de"},
		{"MÜNCHEN.de", "xn--mnchen-3ya.de"},
		{"https://münchen.de/page", "xn--mnchen-3ya.de"},
		{"_dmarc.münchen.de", "_dmarc.xn--mnchen-3ya.de"},
		{"straße.de", "xn--strae-oqa.de"},
		{"例え.jp", "xn--r8jz45g.jp"},

		// Anything else is refused: silently dropping a character would query
		// a name the user never typed.
		{"", ""},
		{".", ""},
		{"http://", ""},
		{"https:///path", ""},
		{"exa mple.com", ""},
		{"contact@example.com", ""},
		{"user:pass@example.com", ""},
		{"foo:example.com", ""},
		{"example.com:http", ""},
		{"example.com:99999", ""},
		{"<script>alert(1)</script>", ""},
		{"exa$mple.com", ""},
		{"exa mplé.com", ""},
		{"a..b.example", ""},
		{".example.com", ""},
		{longLabel, ""},
		{"[not-an-ip]", ""},
		{"fe80::1%eth0", ""},
	}
	for _, tt := range tests {
		if got := sanitizeDomain(tt.input); got != tt.want {
			t.Errorf("sanitizeDomain(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestParseTypePrefix(t *testing.T) {
	mx := []uint16{mdns.TypeMX}
	tests := []struct {
		input     string
		wantTypes []uint16
		wantRest  string
	}{
		{"MX:example.com", mx, "example.com"},
		{"mx:example.com", mx, "example.com"},
		{"MX,NS:example.com", []uint16{mdns.TypeMX, mdns.TypeNS}, "example.com"},
		{"HTTPS:example.com", []uint16{mdns.TypeHTTPS}, "example.com"},
		{"https:example.com", []uint16{mdns.TypeHTTPS}, "example.com"},
		{"AAAA:example.com", []uint16{mdns.TypeAAAA}, "example.com"},
		{"MX:https://example.com", mx, "https://example.com"},
		{"PTR:1.1.1.1", []uint16{mdns.TypePTR}, "1.1.1.1"},

		// ALL is the spelling of "no explicit type": consumed, but no type.
		{"ALL:example.com", nil, "example.com"},
		{"all:example.com", nil, "example.com"},

		// No prefix at all.
		{"example.com", nil, "example.com"},
		{"FOO:example.com", nil, "FOO:example.com"},
		{"A,FOO:example.com", nil, "A,FOO:example.com"},
		{":example.com", nil, ":example.com"},
		{"MX:", nil, "MX:"},

		// A URL scheme is not a record type, even when it reads like one.
		{"https://example.com", nil, "https://example.com"},
		{"HTTPS://example.com/page", nil, "HTTPS://example.com/page"},
		{"http://example.com", nil, "http://example.com"},

		// An IPv6 address is not a prefix, even when its first group is a type.
		{"a::1", nil, "a::1"},
		{"A::1", nil, "A::1"},
		{"aaaa:bbbb::1", nil, "aaaa:bbbb::1"},
		{"a:b:c:d:e:f:1:2", nil, "a:b:c:d:e:f:1:2"},
		{"2001:db8::1", nil, "2001:db8::1"},
	}
	for _, tt := range tests {
		gotTypes, gotRest := parseTypePrefix(tt.input)
		if !reflect.DeepEqual(gotTypes, tt.wantTypes) || gotRest != tt.wantRest {
			t.Errorf("parseTypePrefix(%q) = %v, %q; want %v, %q", tt.input, gotTypes, gotRest, tt.wantTypes, tt.wantRest)
		}
	}
}

func TestRequestedTypes(t *testing.T) {
	tests := map[string]string{
		"":                "",
		"type=MX":         "MX",
		"type=MX,NS":      "MX,NS",
		"type=MX&type=NS": "MX,NS",
		"type=&type=MX":   ",MX",
		"other=1&type=A":  "A",
	}
	for query, want := range tests {
		r := httptest.NewRequest(http.MethodGet, "/lookup?"+query, nil)
		if got := requestedTypes(r); got != want {
			t.Errorf("requestedTypes(%q) = %q, want %q", query, got, want)
		}
	}
}

// ─── Security ─────────────────────────────────────────────────────────────────

// AllowedResolver is the only thing standing between ?resolver= and SSRF.
func TestAllowedResolver(t *testing.T) {
	a := newTestApp(t, "Google=8.8.8.8:53", "Alt=1.1.1.1:5353", "AFNIC=2001:678:8::3")

	allowed := map[string]string{
		"8.8.8.8:53":         "8.8.8.8:53",
		"8.8.8.8":            "8.8.8.8:53",
		" 8.8.8.8:53 ":       "8.8.8.8:53",
		"1.1.1.1:5353":       "1.1.1.1:5353",
		"[2001:678:8::3]:53": "[2001:678:8::3]:53",
		"2001:678:8::3":      "[2001:678:8::3]:53",
	}
	for input, want := range allowed {
		if got, ok := a.AllowedResolver(input); !ok || got != want {
			t.Errorf("AllowedResolver(%q) = %q, %v; want %q", input, got, ok, want)
		}
	}

	refused := []string{
		"",
		"   ",
		// Internal targets.
		"127.0.0.1", "127.0.0.1:53", "localhost:53", "[::1]:53", "::1",
		"10.0.0.1:53", "192.168.1.1:53", "169.254.169.254:53", "169.254.169.254:80",
		// Allowed host, other port.
		"8.8.8.8:5353", "8.8.8.8:80", "1.1.1.1", "1.1.1.1:53",
		// The display name is never accepted as input.
		"Google", "Google=8.8.8.8:53", "Google - 8.8.8.8:53",
		// Tricks around the exact match.
		"8.8.8.8:53,127.0.0.1:53", "8.8.8.8:53#", "http://8.8.8.8:53", "8.8.8.8.:53", "0x08080808:53",
	}
	for _, input := range refused {
		if got, ok := a.AllowedResolver(input); ok {
			t.Errorf("AllowedResolver(%q) accepted as %q", input, got)
		}
	}
}

func TestUnknownResolverIsNeverContacted(t *testing.T) {
	configured := dnstest.New(t, nil)
	other := dnstest.New(t, nil)
	a := newTestApp(t, configured.Addr)

	for name, h := range map[string]http.HandlerFunc{"api": a.ApiHandler, "html": a.LookupHandler} {
		rec := httptest.NewRecorder()
		a := "/x?query=example.com&resolver=" + url.QueryEscape(other.Addr)
		h(rec, httptest.NewRequest(http.MethodGet, a, nil))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", name, rec.Code)
		}
	}
	if got := len(other.Queries()) + len(configured.Queries()); got != 0 {
		t.Errorf("%d queries sent for a refused resolver", got)
	}
}

// DNS content is controlled by whoever owns the zone: it is as hostile as the
// query itself, and both end up in the page.
func TestResultPageEscapesUntrustedContent(t *testing.T) {
	const payload = `<img src=x onerror=alert(1)>`
	record := dnstest.RR(t, `example.com. 300 IN TXT "`+payload+`"`)
	srv := dnstest.New(t, func(_ dnstest.Query, reply *mdns.Msg) bool {
		reply.Answer = []mdns.RR{record}
		return true
	})
	a := newTestApp(t, srv.Addr)

	tests := map[string]string{
		"record value": "/lookup?type=TXT&query=example.com",
		"query":        "/lookup?query=" + url.QueryEscape(`<script>alert(1)</script>`),
		"resolver":     "/lookup?query=example.com&resolver=" + url.QueryEscape(`"><script>alert(1)</script>`),
		"type":         "/lookup?query=example.com&type=" + url.QueryEscape(`"><script>alert(1)</script>`),
	}
	for name, target := range tests {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			a.LookupHandler(rec, httptest.NewRequest(http.MethodGet, target, nil))
			body := rec.Body.String()
			if strings.Contains(body, "<script>alert") || strings.Contains(body, "<img src=x") {
				t.Errorf("unescaped payload in the page:\n%s", body)
			}
		})
	}
}

// ─── Template helpers ─────────────────────────────────────────────────────────

func TestRecordTypeClassCoversTheCatalogue(t *testing.T) {
	a := newTestApp(t)
	class := a.buildFuncMap(a.I18n.Localizer("", ""))["recordTypeClass"].(func(string) string)
	css, err := os.ReadFile("../../static/css/main.css")
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range dns.TypeCatalog {
		for _, name := range g.Types {
			got := class(name)
			if got == "rtype-other" {
				t.Errorf("%s has no class of its own", name)
			}
			if !strings.Contains(string(css), "."+got) {
				t.Errorf("class %s of %s is missing from main.css", got, name)
			}
		}
	}
	if got := class("mx"); got != "rtype-mx" {
		t.Errorf("lowercase type: class = %q", got)
	}
	if got := class("UNKNOWN"); got != "rtype-other" || !strings.Contains(string(css), ".rtype-other") {
		t.Errorf("unknown type: class = %q", got)
	}
}

func TestRcodeClass(t *testing.T) {
	a := newTestApp(t)
	class := a.buildFuncMap(a.I18n.Localizer("", ""))["rcodeClass"].(func(string) string)
	css, err := os.ReadFile("../../static/css/main.css")
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]string{
		"NOERROR":  "rcode-noerror",
		"noerror":  "rcode-noerror",
		"NXDOMAIN": "rcode-nxdomain",
		"SERVFAIL": "rcode-servfail",
		"REFUSED":  "rcode-refused",
		"FORMERR":  "rcode-other",
		"":         "rcode-other",
	}
	for rcode, want := range tests {
		got := class(rcode)
		if got != want {
			t.Errorf("rcodeClass(%q) = %q, want %q", rcode, got, want)
		}
		if !strings.Contains(string(css), "."+got) {
			t.Errorf("class %s is missing from main.css", got)
		}
	}
}

func TestFormatTTL(t *testing.T) {
	a := newTestApp(t)
	format := a.buildFuncMap(a.I18n.Localizer("", ""))["formatTTL"].(func(uint32) string)
	tests := map[uint32]string{
		0:      "0s",
		59:     "59s",
		60:     "1m0s",
		3599:   "59m59s",
		3600:   "1h0m0s",
		86399:  "23h59m59s",
		86400:  "1d",
		90000:  "1d1h0m0s",
		172800: "2d",
	}
	for ttl, want := range tests {
		if got := format(ttl); got != want {
			t.Errorf("formatTTL(%d) = %q, want %q", ttl, got, want)
		}
	}
}

func TestTotalRecords(t *testing.T) {
	a := newTestApp(t)
	total := a.buildFuncMap(a.I18n.Localizer("", ""))["totalRecords"].(func([]model.RecordGroup) int)
	groups := []model.RecordGroup{{Records: make([]model.RecordInfo, 2)}, {}, {Records: make([]model.RecordInfo, 3)}}
	if got := total(groups); got != 5 {
		t.Errorf("totalRecords = %d, want 5", got)
	}
	if got := total(nil); got != 0 {
		t.Errorf("totalRecords(nil) = %d", got)
	}
}
