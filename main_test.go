package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"testing"

	mdns "github.com/miekg/dns"
	"leblanc.io/open-go-base/appconf"
	i18n "leblanc.io/open-go-base/i18n"

	"open-go-dig/internal/config"
	"open-go-dig/internal/dns"
	"open-go-dig/internal/dnstest"
	"open-go-dig/internal/model"
)

const allowedOrigin = "https://app.example"

// startApp runs the complete pipeline against the given resolvers. The limiter
// is off unless the mutators turn it on.
func startApp(t *testing.T, resolvers []string, mutate ...func(*config.Config)) *httptest.Server {
	t.Helper()
	cfg := &config.Config{
		CORS: appconf.CORS{AllowedOrigins: []string{allowedOrigin}, AllowedMethods: []string{"GET", "OPTIONS"}, MaxAge: 300},
	}
	for _, m := range mutate {
		m(cfg)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h, err := newHandler(cfg, dns.NewClient(resolvers, 1, 8), logger)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

// fixtureZone answers for example.com, one CNAME and two reverse names; anything
// else is NXDOMAIN.
func fixtureZone(t *testing.T) *dnstest.Server {
	t.Helper()
	ptrA1, _ := mdns.ReverseAddr("a::1")
	ptrAaaa, _ := mdns.ReverseAddr("aaaa:bbbb::1")
	zone := map[string]map[uint16][]string{
		"example.com.": {
			mdns.TypeA:     {"example.com. 300 IN A 192.0.2.1"},
			mdns.TypeMX:    {"example.com. 300 IN MX 10 mail.example.com."},
			mdns.TypeNS:    {"example.com. 300 IN NS ns.example.com."},
			mdns.TypeHTTPS: {`example.com. 300 IN HTTPS 1 . alpn="h2"`},
		},
		"www.example.com.": {
			mdns.TypeA:     {"www.example.com. 300 IN CNAME example.com.", "example.com. 300 IN A 192.0.2.1"},
			mdns.TypeCNAME: {"www.example.com. 300 IN CNAME example.com."},
			mdns.TypeTXT:   {"www.example.com. 300 IN CNAME example.com."},
		},
		"xn--mnchen-3ya.de.":    {mdns.TypeA: {"xn--mnchen-3ya.de. 300 IN A 192.0.2.2"}},
		"8.8.8.8.in-addr.arpa.": {mdns.TypePTR: {"8.8.8.8.in-addr.arpa. 300 IN PTR dns.google."}},
		ptrA1:                   {mdns.TypePTR: {ptrA1 + " 300 IN PTR a1.example."}},
		ptrAaaa:                 {mdns.TypePTR: {ptrAaaa + " 300 IN PTR aaaa.example."}},
	}
	parsed := map[string]map[uint16][]mdns.RR{}
	for name, types := range zone {
		parsed[name] = map[uint16][]mdns.RR{}
		for typ, records := range types {
			for _, r := range records {
				parsed[name][typ] = append(parsed[name][typ], dnstest.RR(t, r))
			}
		}
	}
	return dnstest.New(t, func(q dnstest.Query, reply *mdns.Msg) bool {
		types, ok := parsed[q.Name]
		if !ok {
			reply.Rcode = mdns.RcodeNameError
			return true
		}
		reply.Answer = types[q.Type]
		return true
	})
}

func get(t *testing.T, target string, headers ...string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, string(body)
}

func apiURL(base, query string, extra ...string) string {
	u := base + "/api/lookup?query=" + url.QueryEscape(query)
	for i := 0; i+1 < len(extra); i += 2 {
		u += "&" + extra[i] + "=" + url.QueryEscape(extra[i+1])
	}
	return u
}

func decodeAPI(t *testing.T, body string) model.APIResponse {
	t.Helper()
	var out model.APIResponse
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, body)
	}
	return out
}

func localizer(t *testing.T, lang string) *i18n.Localizer {
	t.Helper()
	bundle, err := i18n.NewFS(localeFiles, "locales", defaultLanguage)
	if err != nil {
		t.Fatal(err)
	}
	return bundle.Localizer(lang, "")
}

func queriedTypes(queries []dnstest.Query) map[string]bool {
	out := map[string]bool{}
	for _, q := range queries {
		out[dns.TypeName(q.Type)] = true
	}
	return out
}

func sameSet(got map[string]bool, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for _, w := range want {
		if !got[w] {
			return false
		}
	}
	return true
}

// ─── What the user types ──────────────────────────────────────────────────────

func TestLookupInputs(t *testing.T) {
	defaults := dns.DefaultTypeNames()
	reverseA1, _ := mdns.ReverseAddr("a::1")
	reverseAaaa, _ := mdns.ReverseAddr("aaaa:bbbb::1")

	tests := []struct {
		name      string
		query     string
		extra     []string
		wantQuery string   // value reported by the API
		wantName  string   // name sent to the resolver
		wantTypes []string // types sent to the resolver
	}{
		{name: "bare domain", query: "example.com", wantQuery: "example.com", wantName: "example.com.", wantTypes: defaults},
		{name: "http URL", query: "http://example.com", wantQuery: "example.com", wantName: "example.com.", wantTypes: defaults},
		{name: "https URL", query: "https://example.com", wantQuery: "example.com", wantName: "example.com.", wantTypes: defaults},
		{name: "https URL with path", query: "https://example.com/page?x=1", wantQuery: "example.com", wantName: "example.com.", wantTypes: defaults},
		{name: "uppercase https URL", query: "HTTPS://Example.com/", wantQuery: "example.com", wantName: "example.com.", wantTypes: defaults},
		{name: "URL with port", query: "https://example.com:8443/", wantQuery: "example.com", wantName: "example.com.", wantTypes: defaults},
		{name: "https URL with type", query: "https://example.com", extra: []string{"type", "MX"}, wantQuery: "example.com", wantName: "example.com.", wantTypes: []string{"MX"}},

		{name: "type prefix", query: "MX:example.com", wantQuery: "example.com", wantName: "example.com.", wantTypes: []string{"MX"}},
		{name: "lowercase prefix", query: "mx:example.com", wantQuery: "example.com", wantName: "example.com.", wantTypes: []string{"MX"}},
		{name: "HTTPS record prefix", query: "HTTPS:example.com", wantQuery: "example.com", wantName: "example.com.", wantTypes: []string{"HTTPS"}},
		{name: "several prefixes", query: "MX,NS:example.com", wantQuery: "example.com", wantName: "example.com.", wantTypes: []string{"MX", "NS"}},
		{name: "ALL prefix", query: "ALL:example.com", wantQuery: "example.com", wantName: "example.com.", wantTypes: defaults},
		{name: "prefix beats param", query: "MX:example.com", extra: []string{"type", "NS"}, wantQuery: "example.com", wantName: "example.com.", wantTypes: []string{"MX"}},

		{name: "param", query: "example.com", extra: []string{"type", "MX"}, wantQuery: "example.com", wantName: "example.com.", wantTypes: []string{"MX"}},
		{name: "comma param", query: "example.com", extra: []string{"type", "MX,NS"}, wantQuery: "example.com", wantName: "example.com.", wantTypes: []string{"MX", "NS"}},
		{name: "repeated param", query: "example.com", extra: []string{"type", "MX", "type", "NS"}, wantQuery: "example.com", wantName: "example.com.", wantTypes: []string{"MX", "NS"}},
		{name: "default chip plus type", query: "example.com", extra: []string{"type", "", "type", "MX"}, wantQuery: "example.com", wantName: "example.com.", wantTypes: []string{"MX"}},
		{name: "ALL param", query: "example.com", extra: []string{"type", "ALL"}, wantQuery: "example.com", wantName: "example.com.", wantTypes: defaults},
		{name: "unknown param", query: "example.com", extra: []string{"type", "FOO"}, wantQuery: "example.com", wantName: "example.com.", wantTypes: defaults},

		{name: "reverse IPv4", query: "8.8.8.8", wantQuery: "8.8.8.8", wantName: "8.8.8.8.in-addr.arpa.", wantTypes: []string{"PTR"}},
		{name: "reverse ignores type", query: "8.8.8.8", extra: []string{"type", "MX"}, wantQuery: "8.8.8.8", wantName: "8.8.8.8.in-addr.arpa.", wantTypes: []string{"PTR"}},
		{name: "IPv6 reading like type A", query: "a::1", wantQuery: "a::1", wantName: reverseA1, wantTypes: []string{"PTR"}},
		{name: "IPv6 reading like type AAAA", query: "aaaa:bbbb::1", wantQuery: "aaaa:bbbb::1", wantName: reverseAaaa, wantTypes: []string{"PTR"}},

		{name: "IDN", query: "münchen.de", extra: []string{"type", "A"}, wantQuery: "xn--mnchen-3ya.de", wantName: "xn--mnchen-3ya.de.", wantTypes: []string{"A"}},
		{name: "underscore", query: "_dmarc.example.com", extra: []string{"type", "TXT"}, wantQuery: "_dmarc.example.com", wantName: "_dmarc.example.com.", wantTypes: []string{"TXT"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			zone := fixtureZone(t)
			app := startApp(t, []string{zone.Addr})

			resp, body := get(t, apiURL(app.URL, tt.query, tt.extra...))
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d\n%s", resp.StatusCode, body)
			}
			if got := decodeAPI(t, body).Query; got != tt.wantQuery {
				t.Errorf("query = %q, want %q", got, tt.wantQuery)
			}
			queries := zone.Queries()
			if types := queriedTypes(queries); !sameSet(types, tt.wantTypes) {
				t.Errorf("queried types = %v, want %v", types, tt.wantTypes)
			}
			for _, q := range queries {
				if q.Name != tt.wantName {
					t.Errorf("queried name = %q, want %q", q.Name, tt.wantName)
				}
			}
		})
	}
}

// A mistyped input is the client's error: 400, and nothing goes out on the wire.
func TestInvalidInputsAreBadRequests(t *testing.T) {
	inputs := []string{
		"exa mple.com",
		"contact@example.com",
		"FOO:example.com",
		"a..b.example",
		"<script>",
		".",
		"http://",
		strings.Repeat("a", 254),
	}
	zone := fixtureZone(t)
	app := startApp(t, []string{zone.Addr})
	fr := localizer(t, "fr")

	for _, input := range inputs {
		t.Run(input, func(t *testing.T) {
			resp, body := get(t, apiURL(app.URL, input, "lang", "fr"))
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("API status = %d, want 400\n%s", resp.StatusCode, body)
			}
			if got := decodeAPI(t, body).Error; got == "" || got == "error.invalid_input" {
				t.Errorf("API error = %q", got)
			} else if got != fr.T("error.invalid_input") && got != fr.T("error.empty_query") {
				t.Errorf("API error is not localized: %q", got)
			}
			resp, _ = get(t, app.URL+"/lookup?query="+url.QueryEscape(input))
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("HTML status = %d, want 400", resp.StatusCode)
			}
		})
	}
	if got := zone.Queries(); len(got) != 0 {
		t.Errorf("queries sent for invalid inputs: %+v", got)
	}
}

func TestMissingQuery(t *testing.T) {
	app := startApp(t, []string{dnstest.DeadAddr(t)})

	resp, body := get(t, app.URL+"/api/lookup?lang=fr")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("API status = %d", resp.StatusCode)
	}
	if got := decodeAPI(t, body).Error; got != localizer(t, "fr").T("error.missing_query") {
		t.Errorf("API error = %q", got)
	}

	resp, _ = get(t, app.URL+"/lookup")
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/" {
		t.Errorf("HTML: status = %d, Location = %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestUnknownResolverIsABadRequest(t *testing.T) {
	app := startApp(t, []string{fixtureZone(t).Addr})
	resp, body := get(t, apiURL(app.URL, "example.com", "resolver", "127.0.0.1:53", "lang", "fr"))
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d", resp.StatusCode)
	}
	if got := decodeAPI(t, body).Error; got != localizer(t, "fr").T("error.invalid_resolver") {
		t.Errorf("error = %q", got)
	}
}

// ─── What the resolvers answer ────────────────────────────────────────────────

func TestAllResolversDownIsABadGateway(t *testing.T) {
	app := startApp(t, []string{dnstest.DeadAddr(t), dnstest.DeadAddr(t)})

	resp, body := get(t, apiURL(app.URL, "example.com", "type", "NS"))
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("API status = %d, want 502\n%s", resp.StatusCode, body)
	}
	if decodeAPI(t, body).Error == "" {
		t.Errorf("API: no error message\n%s", body)
	}

	resp, body = get(t, app.URL+"/lookup?query=example.com&type=NS")
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("HTML status = %d, want 502", resp.StatusCode)
	}
	if !strings.Contains(body, `class="ed"`) {
		t.Errorf("HTML: error block missing\n%s", body)
	}
}

func TestPartialFailureStaysSuccessful(t *testing.T) {
	record := dnstest.RR(t, "example.com. 300 IN MX 10 mail.example.com.")
	srv := dnstest.New(t, func(q dnstest.Query, reply *mdns.Msg) bool {
		if q.Type == mdns.TypeNS {
			return false
		}
		reply.Answer = []mdns.RR{record}
		return true
	})
	app := startApp(t, []string{srv.Addr})

	resp, body := get(t, apiURL(app.URL, "example.com", "type", "MX,NS"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	out := decodeAPI(t, body)
	if len(out.Warnings) != 1 || len(out.Records) != 1 {
		t.Errorf("warnings = %v, records = %+v", out.Warnings, out.Records)
	}
}

func TestDNSErrorsAreSuccessfulResponses(t *testing.T) {
	zone := fixtureZone(t)
	app := startApp(t, []string{zone.Addr})
	resp, body := get(t, apiURL(app.URL, "nothing.example", "type", "A"))
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d", resp.StatusCode)
	}
	if out := decodeAPI(t, body); out.Rcode != "NXDOMAIN" || out.Error != "" {
		t.Errorf("rcode = %q, error = %q", out.Rcode, out.Error)
	}
}

func TestCNAMEIsListedOnce(t *testing.T) {
	app := startApp(t, []string{fixtureZone(t).Addr})
	_, body := get(t, apiURL(app.URL, "www.example.com"))
	for _, g := range decodeAPI(t, body).Records {
		if g.Type == "CNAME" && len(g.Records) != 1 {
			t.Errorf("CNAME listed %d times", len(g.Records))
		}
	}
}

func TestChosenResolverIsUsed(t *testing.T) {
	first, second := fixtureZone(t), fixtureZone(t)
	app := startApp(t, []string{first.Addr, second.Addr})

	resp, body := get(t, apiURL(app.URL, "example.com", "type", "A", "resolver", second.Addr))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if got := decodeAPI(t, body).Server; got != second.Addr {
		t.Errorf("server = %q, want %q", got, second.Addr)
	}
	if got := first.Queries(); len(got) != 0 {
		t.Errorf("first resolver queried: %+v", got)
	}
}

func TestAPIStatus(t *testing.T) {
	healthy := dnstest.New(t, nil)
	failing := dnstest.New(t, func(_ dnstest.Query, reply *mdns.Msg) bool {
		reply.Rcode = mdns.RcodeRefused
		return true
	})
	dead := dnstest.DeadAddr(t)
	app := startApp(t, []string{healthy.Addr, dead, failing.Addr})

	resp, body := get(t, app.URL+"/api/status")
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		t.Errorf("status = %d, type = %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	var out struct {
		Count     int `json:"count"`
		Resolvers []struct {
			Server string `json:"server"`
			Status string `json:"status"`
		} `json:"resolvers"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	order := []string{}
	for _, r := range out.Resolvers {
		got[r.Server] = r.Status
		order = append(order, r.Server)
	}
	if !reflect.DeepEqual(order, []string{healthy.Addr, dead, failing.Addr}) || out.Count != 3 {
		t.Errorf("order = %v, count = %d", order, out.Count)
	}
	if got[healthy.Addr] != "ok" || got[dead] != "error" || got[failing.Addr] != "error" {
		t.Errorf("statuses = %v", got)
	}
}

// ─── Pages and languages ──────────────────────────────────────────────────────

// A raw key in a page means a translation is missing or misspelled. The .js and
// .css suffixes are the only legitimate lookalikes.
var rawKeyRe = regexp.MustCompile(`\b(?:index|result|about|error|common|nav)\.[a-z_0-9]+\b`)

func rawKeys(body string) []string {
	out := []string{}
	for _, m := range rawKeyRe.FindAllString(body, -1) {
		if !strings.HasSuffix(m, ".js") && !strings.HasSuffix(m, ".css") && !strings.HasSuffix(m, ".html") {
			out = append(out, m)
		}
	}
	return out
}

func TestPagesRenderInEveryLanguage(t *testing.T) {
	zone := fixtureZone(t)
	app := startApp(t, []string{"Fixture=" + zone.Addr})

	pages := []string{"/", "/about", "/lookup?query=example.com", "/lookup?query=8.8.8.8", "/lookup?query=nothing.example"}
	for _, lang := range []string{"en", "fr"} {
		for _, page := range pages {
			sep := "?"
			if strings.Contains(page, "?") {
				sep = "&"
			}
			t.Run(lang+page, func(t *testing.T) {
				resp, body := get(t, app.URL+page+sep+"lang="+lang)
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("status = %d", resp.StatusCode)
				}
				if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
					t.Errorf("Content-Type = %q", resp.Header.Get("Content-Type"))
				}
				if resp.Header.Get("Vary") != "Accept-Language" {
					t.Errorf("Vary = %q", resp.Header.Get("Vary"))
				}
				if !strings.Contains(body, `lang="`+lang+`"`) {
					t.Errorf("page not marked as %s", lang)
				}
				if keys := rawKeys(body); len(keys) != 0 {
					t.Errorf("untranslated keys: %v", keys)
				}
			})
		}
	}
}

func TestLanguageSelection(t *testing.T) {
	app := startApp(t, []string{dnstest.DeadAddr(t)})
	en, fr := localizer(t, "en").T("error.missing_query"), localizer(t, "fr").T("error.missing_query")
	if en == fr {
		t.Fatal("en and fr share the same text: the test proves nothing")
	}
	tests := []struct {
		name   string
		query  string
		header string
		want   string
	}{
		{"default", "", "", en},
		{"header", "", "fr-FR,fr;q=0.9", fr},
		{"param", "?lang=fr", "", fr},
		{"param beats header", "?lang=en", "fr", en},
		{"unknown language", "?lang=xx", "", en},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var headers []string
			if tt.header != "" {
				headers = []string{"Accept-Language", tt.header}
			}
			_, body := get(t, app.URL+"/api/lookup"+tt.query, headers...)
			if got := decodeAPI(t, body).Error; got != tt.want {
				t.Errorf("error = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPickerShowsTheWholeCatalogue(t *testing.T) {
	app := startApp(t, []string{dnstest.DeadAddr(t)})
	_, body := get(t, app.URL+"/")
	for _, g := range dns.TypeCatalog {
		for _, name := range g.Types {
			if !strings.Contains(body, `value="`+name+`"`) {
				t.Errorf("%s missing from the picker", name)
			}
		}
	}
}

func TestResolverPickerShowsLabels(t *testing.T) {
	app := startApp(t, []string{"Fixture=" + fixtureZone(t).Addr})
	_, body := get(t, app.URL+"/")
	if !strings.Contains(body, "Fixture - 127.0.0.1:") {
		t.Errorf("resolver label missing from the page")
	}
}

// ─── Pipeline ─────────────────────────────────────────────────────────────────

func TestRoutes(t *testing.T) {
	app := startApp(t, []string{dnstest.DeadAddr(t)})
	tests := []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/", http.StatusOK},
		{http.MethodGet, "/about", http.StatusOK},
		{http.MethodGet, "/missing", http.StatusNotFound},
		{http.MethodGet, "/static/css/main.css", http.StatusOK},
		{http.MethodGet, "/static/missing.css", http.StatusNotFound},
		{http.MethodPost, "/api/lookup?query=example.com", http.StatusMethodNotAllowed},
		{http.MethodDelete, "/about", http.StatusMethodNotAllowed},
		// The "/" catch-all takes over from "GET /static/" for other methods.
		{http.MethodPost, "/static/css/main.css", http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, app.URL+tt.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != tt.want {
				t.Errorf("status = %d, want %d", resp.StatusCode, tt.want)
			}
		})
	}
}

func assertSecurityHeaders(t *testing.T, h http.Header) {
	t.Helper()
	for _, name := range []string{"X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Content-Security-Policy"} {
		if h.Get(name) == "" {
			t.Errorf("%s missing", name)
		}
	}
}

func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	zone := fixtureZone(t)
	app := startApp(t, []string{zone.Addr})
	for _, path := range []string{"/", "/about", "/missing", "/lookup?query=example.com", "/api/lookup?query=example.com", "/api/lookup", "/api/status", "/static/css/main.css"} {
		t.Run(path, func(t *testing.T) {
			resp, _ := get(t, app.URL+path)
			assertSecurityHeaders(t, resp.Header)
			if !strings.Contains(resp.Header.Get("Link"), "/static/css/main.css") {
				t.Errorf("Link = %q", resp.Header.Get("Link"))
			}
		})
	}
}

func TestCORS(t *testing.T) {
	app := startApp(t, []string{fixtureZone(t).Addr})

	preflight := func(origin string) *http.Response {
		req, err := http.NewRequest(http.MethodOptions, app.URL+"/api/lookup", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Origin", origin)
		req.Header.Set("Access-Control-Request-Method", http.MethodGet)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}

	resp := preflight(allowedOrigin)
	if resp.StatusCode >= 300 {
		t.Errorf("preflight status = %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != allowedOrigin {
		t.Errorf("Allow-Origin = %q", got)
	}
	assertSecurityHeaders(t, resp.Header) // SecurityHeaders wraps CORS

	if got := preflight("https://evil.example").Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("foreign origin allowed: %q", got)
	}

	simple, _ := get(t, apiURL(app.URL, "example.com", "type", "A"), "Origin", allowedOrigin)
	if got := simple.Header.Get("Access-Control-Allow-Origin"); got != allowedOrigin {
		t.Errorf("simple request: Allow-Origin = %q", got)
	}
}

func withRateLimit(n int, trusted ...string) func(*config.Config) {
	return func(c *config.Config) {
		c.Web.RateLimit = n
		c.Web.TrustedProxies = trusted
	}
}

func TestRateLimit(t *testing.T) {
	for _, lang := range []string{"en", "fr"} {
		t.Run(lang, func(t *testing.T) {
			app := startApp(t, []string{dnstest.DeadAddr(t)}, withRateLimit(2))
			for i := range 2 {
				if resp, _ := get(t, app.URL+"/about"); resp.StatusCode != http.StatusOK {
					t.Fatalf("request %d: status = %d", i+1, resp.StatusCode)
				}
			}

			resp, body := get(t, app.URL+"/about", "Accept-Language", lang)
			if resp.StatusCode != http.StatusTooManyRequests {
				t.Fatalf("status = %d, want 429", resp.StatusCode)
			}
			if !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
				t.Errorf("Content-Type = %q", resp.Header.Get("Content-Type"))
			}
			if resp.Header.Get("Retry-After") == "" {
				t.Error("Retry-After missing")
			}
			assertSecurityHeaders(t, resp.Header)
			var out map[string]string
			if err := json.Unmarshal([]byte(body), &out); err != nil {
				t.Fatalf("429 body is not JSON: %v\n%s", err, body)
			}
			if want := localizer(t, lang).T("error.rate_limit"); out["error"] != want {
				t.Errorf("error = %q, want %q", out["error"], want)
			}

			// Static assets stay out of the budget.
			if resp, _ := get(t, app.URL+"/static/css/main.css"); resp.StatusCode != http.StatusOK {
				t.Errorf("static asset limited: status = %d", resp.StatusCode)
			}
		})
	}
}

func TestRateLimitBodyIsValidJSONWhateverTheMessage(t *testing.T) {
	bundle, err := i18n.NewFS(localeFiles, "locales", defaultLanguage)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	rateLimitHandler(bundle).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/?lang=fr", nil))
	if !json.Valid(rec.Body.Bytes()) {
		t.Errorf("invalid JSON: %s", rec.Body.String())
	}
}

// A client must not buy itself a new budget by forging a header…
func TestRateLimitIgnoresForgedForwardedFor(t *testing.T) {
	app := startApp(t, []string{dnstest.DeadAddr(t)}, withRateLimit(2))
	codes := []int{}
	for _, ip := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"} {
		resp, _ := get(t, app.URL+"/about", "X-Forwarded-For", ip)
		codes = append(codes, resp.StatusCode)
	}
	if !reflect.DeepEqual(codes, []int{200, 200, 429}) {
		t.Errorf("statuses = %v", codes)
	}
}

// …but behind a trusted proxy, each real client has its own.
func TestRateLimitHonoursTrustedProxy(t *testing.T) {
	app := startApp(t, []string{dnstest.DeadAddr(t)}, withRateLimit(1, "127.0.0.1/32"))
	for _, ip := range []string{"198.51.100.1", "198.51.100.2"} {
		if resp, _ := get(t, app.URL+"/about", "X-Forwarded-For", ip); resp.StatusCode != http.StatusOK {
			t.Errorf("client %s: status = %d", ip, resp.StatusCode)
		}
	}
	if resp, _ := get(t, app.URL+"/about", "X-Forwarded-For", "198.51.100.1"); resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("repeat client: status = %d, want 429", resp.StatusCode)
	}
}
