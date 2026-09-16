package handler

import (
	"net/http"
	"strings"

	"open-go-dig/internal/dns"
)

type indexView struct {
	Resolvers []dns.Resolver
	// TypeGroups is the record-type catalogue, in display order: the first
	// group is shown inline, the rest behind a disclosure.
	TypeGroups []dns.TypeGroup
	// TypeCount feeds the "N record types" figure so it never drifts from the
	// catalogue.
	TypeCount int
	// DefaultTypeList spells out what the default chip covers, for its
	// tooltip — the chip picks a sweep, not the whole catalogue.
	DefaultTypeList string
}

func (a *App) IndexHandler(w http.ResponseWriter, r *http.Request) {
	loc := a.localizer(r)
	view := indexView{
		Resolvers:  a.DNSClient.Resolvers,
		TypeGroups: dns.TypeCatalog,
		TypeCount:  dns.SupportedTypeCount(),

		DefaultTypeList: strings.Join(dns.DefaultTypeNames(), ", "),
	}
	if err := a.renderLocalized(w, a.indexTmpl, http.StatusOK, loc, view); err != nil {
		a.Logger.Error("render index template", "err", err)
		http.Error(w, loc.T("error.internal"), http.StatusInternalServerError)
		return
	}
}
