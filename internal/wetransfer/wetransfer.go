package wetransfer

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
	apiBaseURL       = "https://wetransfer.com/api/v4/transfers"
	downloadEndpoint = "/download"
	userAgent        = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

var (
	shortURLRegex       = regexp.MustCompile(`^https?://we\.tl/(t-)?([a-zA-Z0-9]+)/?$`)
	fullURLPathRegex    = regexp.MustCompile(`^/downloads/([a-zA-Z0-9]+)/([a-zA-Z0-9]+)/?$`)
	fullURLPathRecRegex = regexp.MustCompile(`^/downloads/([a-zA-Z0-9]+)/([a-zA-Z0-9]+)/([a-zA-Z0-9]+)/?$`)
)

type TransferInfo struct {
	DirectURL string
	FileName  string
	FileSize  int64
	Files     []FileInfo
}

type FileInfo struct {
	ID       string
	Name     string
	Size     int64
	MimeType string
}

type PasswordRequiredError struct{}

func (e *PasswordRequiredError) Error() string {
	return "password required"
}

type Client struct {
	httpClient *http.Client
	userAgent  string
}

func NewClient(requestTimeout time.Duration, maxRedirects int) *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: requestTimeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= maxRedirects {
					return errors.New("too many redirects")
				}
				return nil
			},
		},
		userAgent: userAgent,
	}
}

// Matches reports whether rawURL points at a WeTransfer domain.
func (c *Client) Matches(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(parsed.Host)
	host, _, _ = strings.Cut(host, ":")
	if strings.HasSuffix(host, ".") {
		host = host[:len(host)-1]
	}
	return host == "wetransfer.com" || strings.HasSuffix(host, ".wetransfer.com") ||
		host == "we.tl" || strings.HasSuffix(host, ".we.tl")
}

func (c *Client) Resolve(ctx context.Context, inputURL string, auth map[string]string) (*TransferInfo, error) {
	_, transferID, recipientID, securityHash, err := c.parseURL(ctx, inputURL)
	if err != nil {
		return nil, err
	}

	password := ""
	if auth != nil {
		password = auth["password"]
	}

	directLink, fileName, fileSize, files, err := c.getDirectLink(ctx, transferID, recipientID, securityHash, password)
	if err != nil {
		return nil, err
	}

	return &TransferInfo{
		DirectURL: directLink,
		FileName:  fileName,
		FileSize:  fileSize,
		Files:     files,
	}, nil
}

func (c *Client) parseURL(ctx context.Context, inputURL string) (string, string, string, string, error) {
	parsed, err := url.Parse(inputURL)
	if err != nil {
		return "", "", "", "", fmt.Errorf("invalid URL: %w", err)
	}

	host := strings.ToLower(parsed.Host)
	if !strings.HasSuffix(host, "wetransfer.com") && host != "we.tl" {
		return "", "", "", "", errors.New("domain not allowed: only wetransfer.com and we.tl are supported")
	}

	path := parsed.Path

	if shortURLRegex.MatchString(inputURL) {
		matches := shortURLRegex.FindStringSubmatch(inputURL)
		if len(matches) < 3 {
			return "", "", "", "", errors.New("invalid short URL format")
		}
		prefix := matches[1]
		shortID := matches[2]
		resolved, err := c.resolveShortURL(ctx, prefix+shortID)
		if err != nil {
			return "", "", "", "", err
		}
		return c.parseURL(ctx, resolved)
	}

	if matches := fullURLPathRecRegex.FindStringSubmatch(path); len(matches) == 4 {
		return inputURL, matches[1], matches[2], matches[3], nil
	}

	if matches := fullURLPathRegex.FindStringSubmatch(path); len(matches) == 3 {
		return inputURL, matches[1], "", matches[2], nil
	}

	return "", "", "", "", errors.New("unsupported WeTransfer URL format")
}

func (c *Client) resolveShortURL(ctx context.Context, shortID string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "HEAD", "https://we.tl/"+shortID, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Cache-Control", "max-age=0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to resolve short URL: %w", err)
	}
	defer resp.Body.Close()

	location := resp.Request.URL.String()
	if location == "" {
		return "", errors.New("no redirect location found")
	}

	if strings.Contains(location, "/redirect/error") {
		return "", errors.New("short URL resolution blocked by WeTransfer (likely data center IP). Works on residential IPs. Use full URL instead.")
	}

	return location, nil
}

func (c *Client) getDirectLink(ctx context.Context, transferID, recipientID, securityHash, password string) (string, string, int64, []FileInfo, error) {
	apiURL := apiBaseURL + "/" + transferID + downloadEndpoint

	body := map[string]any{
		"security_hash": securityHash,
		"intent":        "entire_transfer",
	}
	if recipientID != "" {
		body["recipient_id"] = recipientID
	}
	if password != "" {
		body["password"] = password
	}

	jsonBody, _ := json.Marshal(body)

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, strings.NewReader(string(jsonBody)))
	if err != nil {
		return "", "", 0, nil, err
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", "", 0, nil, fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var apiErr struct {
			Message string `json:"message"`
		}
		json.NewDecoder(resp.Body).Decode(&apiErr)
		if apiErr.Message == "invalid_transfer_password" {
			return "", "", 0, nil, &PasswordRequiredError{}
		}
		return "", "", 0, nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, apiErr.Message)
	}

	var result struct {
		DirectLink string `json:"direct_link"`
		Files      []struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Size     int64  `json:"size"`
			MimeType string `json:"mime_type"`
		} `json:"files"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", 0, nil, fmt.Errorf("failed to parse API response: %w", err)
	}

	if result.DirectLink == "" {
		return "", "", 0, nil, errors.New("no direct_link in API response")
	}

	fileName := extractFileName(result.DirectLink)
	var fileSize int64
	files := make([]FileInfo, len(result.Files))
	for i, f := range result.Files {
		files[i] = FileInfo{
			ID:       f.ID,
			Name:     f.Name,
			Size:     f.Size,
			MimeType: f.MimeType,
		}
		fileSize += f.Size
	}
	if fileSize == 0 {
		fileSize = -1
	}

	return result.DirectLink, fileName, fileSize, files, nil
}

func (c *Client) Stream(ctx context.Context, info *TransferInfo, w http.ResponseWriter) (int64, error) {
	const maxRetries = 3
	const baseBackoff = 2 * time.Second
	buf := make([]byte, 32*1024)

	for attempt := 0; attempt <= maxRetries; attempt++ {
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
			if errors.Is(err, context.Canceled) || isClosedConnection(err) {
				return n, nil
			}
			return n, err
		}
		return n, nil
	}
	return 0, nil
}

func extractFileName(directURL string) string {
	parsed, _ := url.Parse(directURL)
	parts := strings.Split(parsed.Path, "/")
	if len(parts) > 0 {
		name := parts[len(parts)-1]
		if name != "" {
			return name
		}
	}
	return "download"
}

func isClosedConnection(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "connection closed") ||
		strings.Contains(errStr, "use of closed network connection")
}
