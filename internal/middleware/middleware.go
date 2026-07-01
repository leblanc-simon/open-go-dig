// Package middleware contains HTTP middlewares used to wrap the application mux.
package middleware

import "net/http"

// Middleware is the standard signature used to chain HTTP handlers.
type Middleware func(http.Handler) http.Handler
