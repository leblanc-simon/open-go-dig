package handler

import (
	"net/http"
	"strings"

	"open-go-dig/internal/model"
)

// resultView is the data passed to the result template — the lookup payload
// plus enough context to re-render the search form (resolver list + chosen).
type resultView struct {
	*model.DNSResult
	Resolvers      []string
	ChosenResolver string
}

func (a *App) LookupHandler(w http.ResponseWriter, r *http.Request) {
	loc := a.localizer(r)

	q := strings.TrimSpace(r.URL.Query().Get("query"))
	if q == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	typeParam := strings.TrimSpace(r.URL.Query().Get("type"))
	resolverParam := strings.TrimSpace(r.URL.Query().Get("resolver"))
	info := a.lookup(r.Context(), q, typeParam, resolverParam, loc)

	statusCode := http.StatusOK
	if info.Error != "" {
		statusCode = http.StatusBadGateway
	}

	// Echo the chosen resolver back to the form only if it passed validation.
	chosen := ""
	if resolverParam != "" {
		if matched, ok := a.AllowedResolver(resolverParam); ok {
			chosen = matched
		}
	}

	view := resultView{
		DNSResult:      info,
		Resolvers:      a.DNSClient.Resolvers,
		ChosenResolver: chosen,
	}

	if err := a.renderLocalized(w, a.resultTmpl, statusCode, loc, view); err != nil {
		a.Logger.Error("render result template", "err", err)
		http.Error(w, loc.T("error.internal"), http.StatusInternalServerError)
		return
	}
}
