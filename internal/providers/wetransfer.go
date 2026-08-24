package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	wtAPIBaseURL       = "https://wetransfer.com/api/v4/transfers"
	wtDownloadEndpoint = "/download"
	wtUserAgent        = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

var (
	wtShortURLRegex       = regexp.MustCompile(`^https?://we\.tl/(t-)?([a-zA-Z0-9]+)/?$`)
	wtFullURLPathRegex    = regexp.MustCompile(`^/downloads/([a-zA-Z0-9]+)/([a-zA-Z0-9]+)/?$`)
	wtFullURLPathRecRegex = regexp.MustCompile(`^/downloads/([a-zA-Z0-9]+)/([a-zA-Z0-9]+)/([a-zA-Z0-9]+)/?$`)
)

type WeTransferClient struct {
	*BaseClient
}

func NewWeTransferClient(cfg ClientConfig) *WeTransferClient {
	if cfg.UserAgent == "" {
		cfg.UserAgent = wtUserAgent
	}
	return &WeTransferClient{BaseClient: NewBaseClient(cfg)}
}

func (c *WeTransferClient) Name() string {
	return "wetransfer"
}

func (c *WeTransferClient) Hosts() []string {
	return []string{"wetransfer.com", "we.tl"}
}

func (c *WeTransferClient) Resolve(ctx context.Context, inputURL, password string) (*TransferInfo, error) {
	transferID, recipientID, securityHash, err := c.parseURL(ctx, inputURL)
	if err != nil {
		return nil, err
	}

	directLink, fileName, fileSize, fileCount, err := c.getDirectLink(ctx, transferID, recipientID, securityHash, password)
	if err != nil {
		return nil, err
	}

	return &TransferInfo{
		DirectURL: directLink,
		FileName:  fileName,
		FileSize:  fileSize,
		FileCount: fileCount,
	}, nil
}

func (c *WeTransferClient) Stream(ctx context.Context, info *TransferInfo, w http.ResponseWriter) (int64, error) {
	const maxRetries = 3
	const baseBackoff = 2 * time.Second
	buf := make([]byte, 32*1024)

	attempt := 0
	for {
		req, err := http.NewRequestWithContext(ctx, "GET", info.DirectURL, nil)
		if err != nil {
			return 0, err
		}
		req.Header.Set("User-Agent", c.userAgent)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			if attempt == maxRetries {
				return 0, fmt.Errorf("upstream failed after %d retries: %w", maxRetries, err)
			}
			select {
			case <-ctx.Done():
				return 0, ctx.Err()
			case <-time.After(baseBackoff * time.Duration(attempt+1)):
			}
			attempt++
			continue
		}

		for k, v := range resp.Header {
			if k == "Content-Type" || k == "Content-Length" || k == "Content-Disposition" || k == "Content-Range" || k == "Accept-Ranges" || k == "ETag" || k == "Last-Modified" {
				for _, vv := range v {
					w.Header().Add(k, vv)
				}
			}
		}
		w.WriteHeader(resp.StatusCode)

		n, err := io.CopyBuffer(w, resp.Body, buf)
		resp.Body.Close()

		if err != nil {
			if IsClientDisconnect(err) {
				return n, nil
			}
			return n, err
		}
		return n, nil
	}
}

func (c *WeTransferClient) parseURL(ctx context.Context, inputURL string) (transferID, recipientID, securityHash string, err error) {
	parsed, err := url.Parse(inputURL)
	if err != nil {
		return "", "", "", fmt.Errorf("invalid URL: %w", err)
	}

	host := parsed.Host
	if !hostAllowed(host) {
		return "", "", "", errors.New("domain not allowed: only wetransfer.com and we.tl are supported")
	}

	path := parsed.Path

	if wtShortURLRegex.MatchString(inputURL) {
		matches := wtShortURLRegex.FindStringSubmatch(inputURL)
		if len(matches) < 3 {
			return "", "", "", errors.New("invalid short URL format")
		}
		prefix := matches[1]
		shortID := matches[2]
		resolved, err := c.resolveShortURL(ctx, prefix+shortID)
		if err != nil {
			return "", "", "", err
		}
		return c.parseURL(ctx, resolved)
	}

	if matches := wtFullURLPathRecRegex.FindStringSubmatch(path); len(matches) == 4 {
		return matches[1], matches[2], matches[3], nil
	}

	if matches := wtFullURLPathRegex.FindStringSubmatch(path); len(matches) == 3 {
		return matches[1], "", matches[2], nil
	}

	return "", "", "", errors.New("unsupported WeTransfer URL format")
}

func (c *WeTransferClient) resolveShortURL(ctx context.Context, shortURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", shortURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to resolve short URL: %w", err)
	}
	defer resp.Body.Close()

	finalURL := resp.Request.URL.String()
	return finalURL, nil
}

type wtDirectLinkResponse struct {
	DirectLink string `json:"direct_link"`
	Files      []struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Size     int64  `json:"size"`
		MimeType string `json:"mime_type"`
	} `json:"files"`
	Error struct {
		Message string `json:"message"`
		Code    string `json:"code"`
	} `json:"error"`
}

func (c *WeTransferClient) getDirectLink(ctx context.Context, transferID, recipientID, securityHash, password string) (string, string, int64, int, error) {
	apiURL := wtAPIBaseURL + "/" + transferID + wtDownloadEndpoint
	if recipientID != "" {
		apiURL += "/" + recipientID
	}
	if securityHash != "" {
		apiURL += "?security_hash=" + securityHash
	}

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, nil)
	if err != nil {
		return "", "", 0, 0, err
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Content-Type", "application/json")
	if password != "" {
		req.Header.Set("x-wetransfer-password", password)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", "", 0, 0, fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	var result wtDirectLinkResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", 0, 0, fmt.Errorf("failed to parse API response: %w", err)
	}

	if result.Error.Message != "" {
		if result.Error.Code == "PASSWORD_REQUIRED" {
			return "", "", 0, 0, &PasswordRequiredError{}
		}
		return "", "", 0, 0, fmt.Errorf("API returned error: %s", result.Error.Message)
	}

	if result.DirectLink == "" {
		return "", "", 0, 0, errors.New("no direct_link in API response")
	}

	fileName := extractFileName(result.DirectLink)
	var fileSize int64
	fileCount := len(result.Files)
	for _, f := range result.Files {
		fileSize += f.Size
	}
	if fileSize == 0 {
		fileSize = -1
	}

	return result.DirectLink, fileName, fileSize, fileCount, nil
}

func extractFileName(directURL string) string {
	parsed, _ := url.Parse(directURL)
	parts := strings.Split(parsed.Path, "/")
	if len(parts) > 0 {
		name := parts[len(parts)-1]
		if idx := strings.Index(name, "?"); idx >= 0 {
			name = name[:idx]
		}
		return name
	}
	return "download"
}

func hostAllowed(host string) bool {
	host = strings.ToLower(host)
	host, _, _ = strings.Cut(host, ":")
	if strings.HasSuffix(host, ".") {
		host = host[:len(host)-1]
	}
	return host == "wetransfer.com" || strings.HasSuffix(host, ".wetransfer.com") ||
		host == "we.tl" || strings.HasSuffix(host, ".we.tl")
}