package handler

import (
	"net/http"

	"open-go-dig/internal/dns"
)

type indexView struct {
	Resolvers []string
	// TypeGroups is the record-type catalogue, in display order: the first
	// group is shown inline, the rest behind a disclosure.
	TypeGroups []dns.TypeGroup
	// TypeCount feeds the "N record types" figure so it never drifts from the
	// catalogue.
	TypeCount int
}

func (a *App) IndexHandler(w http.ResponseWriter, r *http.Request) {
	loc := a.localizer(r)
	view := indexView{
		Resolvers:  a.DNSClient.Resolvers,
		TypeGroups: dns.TypeCatalog,
		TypeCount:  dns.SupportedTypeCount(),
	}
	if err := a.renderLocalized(w, a.indexTmpl, http.StatusOK, loc, view); err != nil {
		a.Logger.Error("render index template", "err", err)
		http.Error(w, loc.T("error.internal"), http.StatusInternalServerError)
		return
	}
}
