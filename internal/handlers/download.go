package handlers

import (
	"errors"
	"fmt"
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

	username := auth.Username(r.Context())
	clientIP := middleware.ClientIP(r)
	start := time.Now()

	provider, err := h.providers.ResolveProvider(urlParam)
	if err != nil {
		h.logDownload(username, clientIP, urlParam, "", nil, 0, err, time.Since(start))
		if errors.Is(err, providers.ErrNoProvider) {
			names := h.providers.GetProviderNames()
			http.Error(w, "This service isn't supported yet. Supported: "+strings.Join(names, ", "), http.StatusBadRequest)
		} else {
			http.Error(w, "Unsupported URL.", http.StatusBadRequest)
		}
		return
	}

	isShortURL := provider.Name() == "wetransfer" && strings.HasPrefix(urlParam, "https://we.tl/")

	info, err := provider.Resolve(ctx, urlParam, r.URL.Query().Get("password"))
	if err != nil {
		h.logDownload(username, clientIP, urlParam, provider.Name(), nil, 0, err, time.Since(start))
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
		if providers.IsFormatError(err) {
			http.Error(w, "Invalid "+provider.Name()+" link format.", http.StatusBadRequest)
			return
		}
		if providers.IsUpstreamError(err) {
			http.Error(w, provider.Name()+" is currently unavailable. Please try again later.", http.StatusBadGateway)
			return
		}
		http.Error(w, "Failed to resolve download: "+err.Error(), http.StatusBadGateway)
		return
	}

	if info.FileSize > int64(h.cfg.Limits.MaxFileSizeGB)*1024*1024*1024 {
		h.logDownload(username, clientIP, urlParam, provider.Name(), nil, 0, errors.New("file too large"), time.Since(start))
		http.Error(w, "File too large", http.StatusRequestEntityTooLarge)
		return
	}

	disposition := "attachment"
	if strings.HasPrefix(info.FileName, "video/") || strings.HasPrefix(info.FileName, "image/") {
		disposition = "inline"
	}

	safeName := sanitizeFilename(info.FileName)
	w.Header().Set("Content-Disposition", disposition+"; filename=\""+safeName+"\"")
	if info.FileSize > 0 {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", info.FileSize))
	}

	n, err := provider.Stream(ctx, info, w)
	h.logDownload(username, clientIP, urlParam, provider.Name(), info, n, err, time.Since(start))
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
		h.logDownload(username, clientIP, urlParam, "", nil, 0, err, time.Since(start))
		if errors.Is(err, providers.ErrNoProvider) {
			names := h.providers.GetProviderNames()
			http.Error(w, "This service isn't supported yet. Supported: "+strings.Join(names, ", "), http.StatusBadRequest)
		} else {
			http.Error(w, "Unsupported URL.", http.StatusBadRequest)
		}
		return
	}

	isShortURL := provider.Name() == "wetransfer" && strings.HasPrefix(urlParam, "https://we.tl/")

	info, err := provider.Resolve(ctx, urlParam, r.URL.Query().Get("password"))
	if err != nil {
		h.logDownload(username, clientIP, urlParam, provider.Name(), nil, 0, err, time.Since(start))
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
		if providers.IsFormatError(err) {
			http.Error(w, "Invalid "+provider.Name()+" link format.", http.StatusBadRequest)
			return
		}
		if providers.IsUpstreamError(err) {
			http.Error(w, provider.Name()+" is currently unavailable. Please try again later.", http.StatusBadGateway)
			return
		}
		http.Error(w, "Failed to resolve: "+err.Error(), http.StatusBadGateway)
		return
	}

	h.audit.AddEvent(audit.Event{
		Time:             time.Now(),
		Action:           "info_check",
		User:             username,
		IP:               clientIP,
		Detail:           "success",
		URL:              urlParam,
		Provider:         provider.Name(),
		Filename:         info.FileName,
		FileSize:         info.FileSize,
		ResolvedURL:      info.DirectURL,
		BytesTransferred: 0,
		DurationMS:       time.Since(start).Milliseconds(),
		SHA256:           "",
		ClientUA:         r.UserAgent(),
	})

	audit.WriteJSON(w, map[string]any{
		"provider":   provider.Name(),
		"filename":   info.FileName,
		"size":       info.FileSize,
		"size_human": audit.FormatBytes(info.FileSize),
		"file_count": info.FileCount,
		"is_short":   isShortURL,
	})
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
		http.Error(w, "Short links can't be resolved from data center IPs. Use the full WeTransfer download link instead.", http.StatusBadGateway)
		return
	}
	http.Error(w, "Failed to resolve short URL. Try the full WeTransfer link.", http.StatusBadGateway)
}

func (h *DownloadHandler) logDownload(username, clientIP, urlParam, providerName string, info *providers.TransferInfo, n int64, err error, dur time.Duration) {
	action := "download_success"
	detail := "success"
	sha256Sum := ""
	filename := ""
	filesize := int64(0)
	resolvedURL := ""

	if info != nil {
		filename = info.FileName
		filesize = info.FileSize
		resolvedURL = info.DirectURL
	}

	if err != nil {
		detail = "error: " + err.Error()
		action = "download_error"
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
		ResolvedURL:      resolvedURL,
		BytesTransferred: n,
		DurationMS:       dur.Milliseconds(),
		SHA256:           sha256Sum,
		ClientUA:         "",
	})
}
