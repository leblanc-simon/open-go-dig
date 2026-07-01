package handler

import (
	"encoding/json"
	"net/http"

	"open-go-dig/internal/dns"
)

// StatusHandler exposes the state of configured DNS resolvers.
func (a *App) StatusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	type resolverStatus struct {
		Server  string `json:"server"`
		Latency string `json:"latency"`
		Status  string `json:"status"`
	}

	var resolvers []resolverStatus
	for _, srv := range a.DNSClient.Resolvers {
		latency, err := dns.CheckResolver(r.Context(), srv, a.DNSClient.Timeout)
		status := "ok"
		if err != nil {
			status = "error"
		}
		resolvers = append(resolvers, resolverStatus{
			Server:  srv,
			Latency: latency.String(),
			Status:  status,
		})
	}

	if err := json.NewEncoder(w).Encode(map[string]any{
		"resolvers": resolvers,
		"count":     len(resolvers),
	}); err != nil {
		a.Logger.Error("encode status response", "err", err)
	}
}
