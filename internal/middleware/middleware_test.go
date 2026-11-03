package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func serve(m Middleware) (*httptest.ResponseRecorder, bool) {
	called := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })
	rec := httptest.NewRecorder()
	m(next).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	return rec, called
}

func TestSecurityHeaders(t *testing.T) {
	rec, called := serve(SecurityHeaders())
	if !called {
		t.Fatal("next handler not called")
	}
	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "SAMEORIGIN",
		"Referrer-Policy":        "strict-origin-when-cross-origin",
	}
	for name, value := range want {
		if got := rec.Header().Get(name); got != value {
			t.Errorf("%s = %q, want %q", name, got, value)
		}
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("Content-Security-Policy = %q, want a default-src 'self' policy", csp)
	}
}

func TestLink(t *testing.T) {
	rec, called := serve(Link())
	if !called {
		t.Fatal("next handler not called")
	}
	link := rec.Header().Get("Link")
	if !strings.Contains(link, "</static/css/main.css>; rel=preload; as=style") {
		t.Errorf("Link = %q, want a preload of main.css", link)
	}
	if got := strings.Count(link, "as=font"); got != 3 {
		t.Errorf("Link announces %d fonts, want 3: %q", got, link)
	}
}
