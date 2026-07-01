package handler

import (
	"encoding/json"
	"net/http"
	"strings"
)

// ApiHandler returns structured data as JSON.
func (a *App) ApiHandler(w http.ResponseWriter, r *http.Request) {
	loc := a.localizer(r)

	q := strings.TrimSpace(r.URL.Query().Get("query"))
	if q == "" {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		if err := json.NewEncoder(w).Encode(map[string]string{"error": loc.T("error.missing_query")}); err != nil {
			a.Logger.Error("encode api error response", "err", err)
		}
		return
	}

	typeParam := strings.TrimSpace(r.URL.Query().Get("type"))
	resolverParam := strings.TrimSpace(r.URL.Query().Get("resolver"))
	info := a.lookup(r.Context(), q, typeParam, resolverParam, loc)

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if info.Error != "" {
		w.WriteHeader(http.StatusBadGateway)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(info.ToAPIResponse()); err != nil {
		a.Logger.Error("encode api response", "err", err)
	}
}
