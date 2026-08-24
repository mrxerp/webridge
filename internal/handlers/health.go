package handlers

import (
	"net/http"

	"webridge/internal/audit"
)

func Healthz(w http.ResponseWriter, r *http.Request) {
	audit.WriteJSON(w, map[string]string{"status": "ok"})
}

func Readyz(w http.ResponseWriter, r *http.Request) {
	audit.WriteJSON(w, map[string]string{"status": "ready"})
}
