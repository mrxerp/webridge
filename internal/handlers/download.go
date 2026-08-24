package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"webridge/internal/audit"
	"webridge/internal/auth"
	"webridge/internal/config"
	"webridge/internal/middleware"
	"webridge/internal/providers"
)

type DownloadHandler struct {
	cfg       *config.Config
	logger    *slog.Logger
	sem       chan struct{}
	audit     *audit.Log
	providers *providers.Registry
}

func NewDownloadHandler(cfg *config.Config, logger *slog.Logger, auditLog *audit.Log, providers *providers.Registry) *DownloadHandler {
	maxConcurrent := cfg.Limits.MaxConcurrentDownloads
	if maxConcurrent <= 0 {
		maxConcurrent = 50
	}
	return &DownloadHandler{
		cfg:       cfg,
		logger:    logger,
		sem:       make(chan struct{}, maxConcurrent),
		audit:     auditLog,
		providers: providers,
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

func (h *DownloadHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	urlParam := h.urlParamOr400(w, r)
	if urlParam == "" {
		return
	}

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

	provider, err := h.providers.ResolveProvider(urlParam)
	if err != nil {
		h.logDownload(username, clientIP, urlParam, nil, 0, err, time.Since(start))
		http.Error(w, "Unsupported URL.", http.StatusBadRequest)
		return
	}

	isShortURL := provider.Name() == "wetransfer" && (strings.HasPrefix(urlParam, "https://we.tl/") || strings.HasPrefix(urlParam, "http://we.tl/"))

	info, err := provider.Resolve(ctx, urlParam, r.URL.Query().Get("password"))
	if err != nil {
		h.logDownload(username, clientIP, urlParam, nil, 0, err, time.Since(start))
		var pwErr *providers.PasswordRequiredError
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
			h.logDownload(username, clientIP, urlParam, info, 0, errors.New("file too large"), time.Since(start))
			http.Error(w, "File size exceeds limit", http.StatusRequestEntityTooLarge)
			return
		}
	}

	w.Header().Set("Content-Disposition", `attachment; filename="`+sanitizeFilename(info.FileName)+`"`)
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	var hashHex string
	streamW := w
	if h.cfg.Audit.HashDownloads && info.FileSize > 0 && info.FileSize <= int64(h.cfg.Audit.MaxHashSizeMB)*1024*1024 {
		hw := &hashWriter{ResponseWriter: w, h: sha256.New()}
		streamW = hw
		defer func() {
			hashHex = hex.EncodeToString(hw.h.Sum(nil))
		}()
	}

	n, err := provider.Stream(ctx, info, streamW)
	if err != nil {
		if !providers.IsClientDisconnect(err) {
			h.logger.Error("stream error", "error", err, "url", urlParam)
		}
		h.logDownload(username, clientIP, urlParam, info, n, err, time.Since(start))
		return
	}

	h.audit.AddEvent(audit.Event{
		Time:             time.Now(),
		Action:           "download_success",
		User:             username,
		IP:               clientIP,
		Detail:           "success",
		URL:              urlParam,
		Provider:         provider.Name(),
		Filename:         info.FileName,
		FileSize:         info.FileSize,
		MimeType:         "",
		ResolvedURL:      info.DirectURL,
		BytesTransferred: n,
		DurationMS:       time.Since(start).Milliseconds(),
		SHA256:           hashHex,
		AnomalyFlags:     nil,
		ClientUA:         r.UserAgent(),
	})
}

func (h *DownloadHandler) InfoHandler(w http.ResponseWriter, r *http.Request) {
	urlParam := h.urlParamOr400(w, r)
	if urlParam == "" {
		return
	}

	ctx := r.Context()
	start := time.Now()
	clientIP := middleware.ClientIP(r)
	username := auth.Username(r.Context())
	h.audit.Add("info_check", username, clientIP, urlParam)

	provider, err := h.providers.ResolveProvider(urlParam)
	if err != nil {
		h.logDownload(username, clientIP, urlParam, nil, 0, err, time.Since(start))
		http.Error(w, "Unsupported URL. Only WeTransfer links are supported.", http.StatusBadRequest)
		return
	}

	isShortURL := provider.Name() == "wetransfer" && (strings.HasPrefix(urlParam, "https://we.tl/") || strings.HasPrefix(urlParam, "http://we.tl/"))

	info, err := provider.Resolve(ctx, urlParam, r.URL.Query().Get("password"))
	if err != nil {
		h.logDownload(username, clientIP, urlParam, nil, 0, err, time.Since(start))
		var pwErr *providers.PasswordRequiredError
		if errors.As(err, &pwErr) {
			w.Header().Set("Content-Type", "application/json")
			audit.WriteJSON(w, map[string]any{
				"needs_password": true,
				"error":          "This transfer is password-protected",
			})
			return
		}
		h.logger.Warn("resolve failed", "url", urlParam, "error", err.Error())
		if isShortURL {
			shortURLError(w, err)
			return
		}
		http.Error(w, "Failed to resolve: "+err.Error(), http.StatusBadGateway)
		return
	}

	h.audit.AddEvent(audit.Event{
		Time:           time.Now(),
		Action:         "info_check",
		User:           username,
		IP:             clientIP,
		Detail:         "success",
		URL:            urlParam,
		Provider:       provider.Name(),
		Filename:       info.FileName,
		FileSize:       info.FileSize,
		MimeType:       "",
		ResolvedURL:    info.DirectURL,
		BytesTransferred: 0,
		DurationMS:     time.Since(start).Milliseconds(),
		SHA256:         "",
		AnomalyFlags:   nil,
		ClientUA:       r.UserAgent(),
	})

	resp := map[string]any{
		"provider":    provider.Name(),
		"filename":    info.FileName,
		"size":        info.FileSize,
		"size_human":  audit.FormatBytes(info.FileSize),
		"file_count":  info.FileCount,
		"is_short":    isShortURL,
	}

	audit.WriteJSON(w, resp)
}

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

func shortURLError(w http.ResponseWriter, err error) {
	if strings.Contains(err.Error(), "redirect/error") || strings.Contains(err.Error(), "data center IP") {
		http.Error(w, "Short WeTransfer links (we.tl/...) are blocked by WeTransfer from data center IPs. This server may be on a data center IP range.", http.StatusBadGateway)
	} else {
		http.Error(w, "Failed to resolve short URL. Try the full WeTransfer link.", http.StatusBadGateway)
	}
}

func (h *DownloadHandler) logDownload(username, clientIP, urlParam string, info *providers.TransferInfo, n int64, err error, dur time.Duration) {
	action := "download_success"
	detail := "success"
	sha256Sum := ""
	providerName := ""
	filename := ""
	filesize := int64(0)
	resolvedURL := ""

	if info != nil {
		providerName = providerFromURL(urlParam)
		filename = info.FileName
		filesize = info.FileSize
		resolvedURL = info.DirectURL
	}

	if err != nil {
		detail = "error: " + err.Error()
		action = "download_error"
	}

	if info != nil && providerName == "" {
		providerName = providerFromURL(urlParam)
	}

	h.audit.AddEvent(audit.Event{
		Time:             time.Now(),
		Action:           action,
		User:             username,
		IP:               clientIP,
		Detail:           detail,
		URL:              urlParam,
		Provider:         providerName,
		Filename:         filename,
		FileSize:         filesize,
		MimeType:         "",
		ResolvedURL:      resolvedURL,
		BytesTransferred: n,
		DurationMS:       dur.Milliseconds(),
		SHA256:           sha256Sum,
		AnomalyFlags:     nil,
		ClientUA:         "",
	})
}

func providerFromURL(url string) string {
	if strings.Contains(url, "wetransfer") || strings.Contains(url, "we.tl") {
		return "wetransfer"
	}
	if strings.Contains(url, "sendgb") {
		return "sendgb"
	}
	if strings.Contains(url, "transfernow") {
		return "transfernow"
	}
	if strings.Contains(url, "wesendit") {
		return "wesendit"
	}
	if strings.Contains(url, "sendspace") {
		return "sendspace"
	}
	return "unknown"
}

type hashWriter struct {
	http.ResponseWriter
	h hash.Hash
}

func (hw *hashWriter) Write(p []byte) (int, error) {
	n, err := hw.ResponseWriter.Write(p)
	hw.h.Write(p[:n])
	return n, err
}