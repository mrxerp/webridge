package handlers

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"proxy-downloader/internal/audit"
	"proxy-downloader/internal/auth"
	"proxy-downloader/internal/config"
	"proxy-downloader/internal/middleware"
	"proxy-downloader/internal/wetransfer"
)

type DownloadHandler struct {
	cfg    *config.Config
	logger *slog.Logger
	sem    chan struct{}
	audit  *audit.Log
	wt     *wetransfer.Client
}

func NewDownloadHandler(cfg *config.Config, logger *slog.Logger, auditLog *audit.Log, wt *wetransfer.Client) *DownloadHandler {
	maxConcurrent := cfg.Limits.MaxConcurrentDownloads
	if maxConcurrent <= 0 {
		maxConcurrent = 50
	}
	return &DownloadHandler{
		cfg:    cfg,
		logger: logger,
		sem:    make(chan struct{}, maxConcurrent),
		audit:  auditLog,
		wt:     wt,
	}
}

// urlParamOr400 returns the validated url query param, or "" after writing
// the error response.
func (h *DownloadHandler) urlParamOr400(w http.ResponseWriter, r *http.Request) string {
	url := r.URL.Query().Get("url")
	if url == "" {
		http.Error(w, "Missing 'url' parameter", http.StatusBadRequest)
		return ""
	}
	if len(url) > h.cfg.UI.MaxURLLength {
		http.Error(w, "URL too long", http.StatusBadRequest)
		return ""
	}
	return url
}

func passwordAuth(r *http.Request) map[string]string {
	if pw := r.URL.Query().Get("password"); pw != "" {
		return map[string]string{"password": pw}
	}
	return nil
}

func isShortWeTransferURL(u string) bool {
	return strings.HasPrefix(u, "https://we.tl/") || strings.HasPrefix(u, "http://we.tl/")
}

func shortURLError(w http.ResponseWriter, err error) {
	if strings.Contains(err.Error(), "redirect/error") || strings.Contains(err.Error(), "data center IP") {
		http.Error(w, "Short WeTransfer links (we.tl/...) are blocked by WeTransfer from data center IPs. This server may be on a data center IP. Solution: Use the full download link (https://wetransfer.com/downloads/...). On a residential IP server, short links work automatically.", http.StatusBadGateway)
		return
	}
	http.Error(w, "Short WeTransfer link error: "+err.Error(), http.StatusBadGateway)
}

func (h *DownloadHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	urlParam := h.urlParamOr400(w, r)
	if urlParam == "" {
		return
	}
	isShortURL := isShortWeTransferURL(urlParam)

	ctx := r.Context()

	select {
	case h.sem <- struct{}{}:
		defer func() { <-h.sem }()
	case <-time.After(30 * time.Second):
		http.Error(w, "Server busy, try again later", http.StatusServiceUnavailable)
		return
	}

	start := time.Now()
	clientIP := middleware.ClientIP(r)
	username := auth.Username(r.Context())
	h.audit.StartDownload()

	if !h.wt.Matches(urlParam) {
		h.logDownload(username, clientIP, urlParam, "", 0, 0, time.Since(start), "error", "unsupported provider")
		http.Error(w, "Unsupported URL. Only WeTransfer links are supported.", http.StatusBadRequest)
		return
	}

	info, err := h.wt.Resolve(ctx, urlParam, passwordAuth(r))
	if err != nil {
		h.logDownload(username, clientIP, urlParam, "", 0, 0, time.Since(start), "error", err.Error())
		var pwErr *wetransfer.PasswordRequiredError
		if errors.As(err, &pwErr) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			audit.WriteJSON(w, map[string]any{
				"needs_password": true,
				"error":          "This transfer is password-protected",
			})
			return
		}
		if isShortURL {
			shortURLError(w, err)
			return
		}
		http.Error(w, "Failed to resolve download: "+err.Error(), http.StatusBadGateway)
		return
	}

	if info.FileSize > 0 {
		maxSize := int64(h.cfg.Limits.MaxFileSizeGB) * 1024 * 1024 * 1024
		if info.FileSize > maxSize {
			h.logDownload(username, clientIP, urlParam, info.FileName, info.FileSize, 0, time.Since(start), "error", "file too large")
			http.Error(w, "File size exceeds limit", http.StatusRequestEntityTooLarge)
			return
		}
	}

	w.Header().Set("Content-Disposition", `attachment; filename="`+sanitizeFilename(info.FileName)+`"`)
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	if err := h.wt.Stream(ctx, info, w); err != nil {
		if !isClientDisconnect(err) {
			h.logger.Error("stream error", "error", err, "url", urlParam)
		}
		h.logDownload(username, clientIP, urlParam, info.FileName, info.FileSize, 0, time.Since(start), "error", err.Error())
		return
	}

	h.logDownload(username, clientIP, urlParam, info.FileName, info.FileSize, info.FileSize, time.Since(start), "success", "")
}

func (h *DownloadHandler) logDownload(username, clientIP, url, filename string, size, bytes int64, duration time.Duration, status, errMsg string) {
	h.logger.Info("download",
		"user", username,
		"ip", clientIP,
		"url", url,
		"filename", filename,
		"size", size,
		"bytes_transferred", bytes,
		"duration_ms", duration.Milliseconds(),
		"status", status,
		"error", errMsg,
	)
	detail := filename
	if errMsg != "" {
		detail = filename + " — " + errMsg
	}
	h.audit.EndDownload(status == "success", bytes)
	h.audit.AddEvent(audit.Event{
		Time:   time.Now(),
		Action: "download_" + status,
		User:   username,
		IP:     clientIP,
		Detail: detail,
		URL:    url,
	})
}

// RecentHandler serves the current user's last download attempts (newest
// first) for the Downloads tab "Recent" list.
func (h *DownloadHandler) RecentHandler(w http.ResponseWriter, r *http.Request) {
	username := auth.Username(r.Context())
	events := h.audit.Query(audit.Query{User: username, Limit: 100})
	recent := make([]audit.Event, 0, 10)
	for _, e := range events {
		if strings.HasPrefix(e.Action, "download_") {
			recent = append(recent, e)
			if len(recent) == 10 {
				break
			}
		}
	}
	audit.WriteJSON(w, map[string]any{"downloads": recent})
}

func sanitizeFilename(name string) string {
	name = strings.ReplaceAll(name, "\"", "'")
	name = strings.ReplaceAll(name, "\n", "")
	name = strings.ReplaceAll(name, "\r", "")
	if len(name) > 255 {
		name = name[:255]
	}
	return name
}

func isClientDisconnect(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "context canceled") ||
		strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "connection closed") ||
		strings.Contains(errStr, "use of closed network connection")
}

func (h *DownloadHandler) InfoHandler(w http.ResponseWriter, r *http.Request) {
	urlParam := h.urlParamOr400(w, r)
	if urlParam == "" {
		return
	}

	ctx := r.Context()
	if !h.wt.Matches(urlParam) {
		http.Error(w, "Unsupported URL. Only WeTransfer links are supported.", http.StatusBadRequest)
		return
	}
	h.audit.Add("info_check", auth.Username(ctx), middleware.ClientIP(r), urlParam)

	isShortURL := isShortWeTransferURL(urlParam)

	info, err := h.wt.Resolve(ctx, urlParam, passwordAuth(r))
	if err != nil {
		var pwErr *wetransfer.PasswordRequiredError
		if errors.As(err, &pwErr) {
			w.Header().Set("Content-Type", "application/json")
			audit.WriteJSON(w, map[string]any{
				"needs_password": true,
				"error":          "This transfer is password-protected",
			})
			return
		}
		if isShortURL {
			shortURLError(w, err)
			return
		}
		http.Error(w, "Failed to resolve: "+err.Error(), http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")

	resp := map[string]any{
		"provider":   "wetransfer",
		"filename":   info.FileName,
		"size":       info.FileSize,
		"size_human": audit.FormatBytes(info.FileSize),
		"file_count": len(info.Files),
		"files":      info.Files,
	}

	if info.FileSize > 0 {
		resp["expires_in"] = "7 days"
	}

	audit.WriteJSON(w, resp)
}
