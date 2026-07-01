package handler

import (
	"net/http"
)

type indexView struct {
	Resolvers []string
}

func (a *App) IndexHandler(w http.ResponseWriter, r *http.Request) {
	loc := a.localizer(r)
	view := indexView{Resolvers: a.DNSClient.Resolvers}
	if err := a.renderLocalized(w, a.indexTmpl, http.StatusOK, loc, view); err != nil {
		a.Logger.Error("render index template", "err", err)
		http.Error(w, loc.T("error.internal"), http.StatusInternalServerError)
		return
	}
}
