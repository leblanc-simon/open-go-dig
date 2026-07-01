package handler

import (
	"net/http"
)

func (a *App) AboutHandler(w http.ResponseWriter, r *http.Request) {
	loc := a.localizer(r)
	if err := a.renderLocalized(w, a.aboutTmpl, http.StatusOK, loc, nil); err != nil {
		a.Logger.Error("render about template", "err", err)
		http.Error(w, loc.T("error.internal"), http.StatusInternalServerError)
		return
	}
}
