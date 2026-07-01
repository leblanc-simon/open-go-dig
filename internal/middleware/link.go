package middleware

import (
	"net/http"
	"strings"
)

// Link emits an HTTP Link header advertising preload hints for the
// critical above-the-fold assets.
func Link() Middleware {
	header := strings.Join([]string{
		"</static/css/main.css>; rel=preload; as=style",
		"</static/fonts/space-mono-400-latin.woff2>; rel=preload; as=font; type=font/woff2; crossorigin",
		"</static/fonts/space-mono-700-latin.woff2>; rel=preload; as=font; type=font/woff2; crossorigin",
		"</static/fonts/syne-400-800-latin.woff2>; rel=preload; as=font; type=font/woff2; crossorigin",
	}, ", ")
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Link", header)
			next.ServeHTTP(w, r)
		})
	}
}
