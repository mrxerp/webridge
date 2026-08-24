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
	wesenditAPIBaseURL = "https://wesendit.com/api/v1"
	wesenditUserAgent  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
)

var (
	wesenditShortURLRegex = regexp.MustCompile(`^https?://wesendit\.com/([a-zA-Z0-9]+)/?$`)
	wesenditFileURLRegex  = regexp.MustCompile(`^https?://wesendit\.com/d/([a-zA-Z0-9]+)/?$`)
)

type WesenditClient struct {
	*BaseClient
}

func NewWesenditClient(cfg ClientConfig) *WesenditClient {
	if cfg.UserAgent == "" {
		cfg.UserAgent = wesenditUserAgent
	}
	return &WesenditClient{BaseClient: NewBaseClient(cfg)}
}

func (c *WesenditClient) Name() string {
	return "wesendit"
}

func (c *WesenditClient) Hosts() []string {
	return []string{"wesendit.com"}
}

func (c *WesenditClient) Resolve(ctx context.Context, inputURL, password string) (*TransferInfo, error) {
	transferID, err := c.parseURL(inputURL)
	if err != nil {
		return nil, err
	}

	directLink, fileName, fileSize, fileCount, err := c.getTransferInfo(ctx, transferID, password)
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

func (c *WesenditClient) Stream(ctx context.Context, info *TransferInfo, w http.ResponseWriter) (int64, error) {
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

func (c *WesenditClient) parseURL(inputURL string) (string, error) {
	parsed, err := url.Parse(inputURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}

	host := strings.ToLower(parsed.Host)
	if host != "wesendit.com" {
		return "", errors.New("domain not allowed: only wesendit.com is supported")
	}


	if matches := wesenditShortURLRegex.FindStringSubmatch(inputURL); len(matches) == 2 {
		return matches[1], nil
	}

	if matches := wesenditFileURLRegex.FindStringSubmatch(inputURL); len(matches) == 2 {
		return matches[1], nil
	}

	return "", errors.New("unsupported Wesendit URL format")
}

type wesenditTransferResponse struct {
	Files []struct {
		Name     string `json:"name"`
		Size     int64  `json:"size"`
		Download string `json:"download_url"`
	} `json:"files"`
	Error string `json:"error"`
}

func (c *WesenditClient) getTransferInfo(ctx context.Context, transferID, password string) (string, string, int64, int, error) {
	apiURL := wesenditAPIBaseURL + "/transfer/" + transferID
	if password != "" {
		apiURL += "?password=" + url.QueryEscape(password)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return "", "", 0, 0, err
	}
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", "", 0, 0, fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	var result wesenditTransferResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", 0, 0, fmt.Errorf("failed to parse API response: %w", err)
	}

	if result.Error != "" {
		if strings.Contains(strings.ToLower(result.Error), "password") {
			return "", "", 0, 0, &PasswordRequiredError{}
		}
		return "", "", 0, 0, fmt.Errorf("API error: %s", result.Error)
	}

	if len(result.Files) == 0 {
		return "", "", 0, 0, errors.New("no files in transfer")
	}

	firstFile := result.Files[0]
	var totalSize int64
	for _, f := range result.Files {
		totalSize += f.Size
	}

	return firstFile.Download, firstFile.Name, totalSize, len(result.Files), nil
}