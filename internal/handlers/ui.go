package handlers

import (
	"embed"
	"net/http"
	"strings"

	"webridge/internal/config"
)

//go:embed index.html app.js style.css
var uiFS embed.FS

func UIHandler(cfg *config.Config) http.Handler {
	if !cfg.UI.Enabled {
		return http.NotFoundHandler()
	}

	indexHTML, _ := uiFS.ReadFile("index.html")
	indexHTMLStr := string(indexHTML)
	indexHTMLStr = strings.ReplaceAll(indexHTMLStr, "{{TITLE}}", cfg.UI.Title)

	fileServer := http.FileServer(http.FS(uiFS))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// ponytail: assets are embedded and tiny, so no-cache is fine; add hashed filenames + long cache if this ever serves large assets
		w.Header().Set("Cache-Control", "no-cache")
		if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
			w.Write([]byte(indexHTMLStr))
			return
		}
		fileServer.ServeHTTP(w, r)
	})
}
