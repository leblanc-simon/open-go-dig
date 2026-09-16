package handler

import (
	"encoding/json"
	"net/http"
	"sync"

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

	// Probe every resolver at once: a dead one would otherwise make the whole
	// page wait out its timeout before the next is even tried. The slice is
	// pre-sized so the configured order survives the fan-out.
	resolvers := make([]resolverStatus, len(a.DNSClient.Resolvers))
	var wg sync.WaitGroup
	for i, srv := range a.DNSClient.Resolvers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			latency, err := dns.CheckResolver(r.Context(), srv, a.DNSClient.Timeout)
			status := "ok"
			if err != nil {
				status = "error"
			}
			resolvers[i] = resolverStatus{
				Server:  srv,
				Latency: latency.String(),
				Status:  status,
			}
		}()
	}
	wg.Wait()

	if err := json.NewEncoder(w).Encode(map[string]any{
		"resolvers": resolvers,
		"count":     len(resolvers),
	}); err != nil {
		a.Logger.Error("encode status response", "err", err)
	}
}
