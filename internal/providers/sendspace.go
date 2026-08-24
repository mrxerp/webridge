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
	sendspaceAPIBaseURL = "https://www.sendspace.com/api"
	sendspaceUserAgent  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
)

var (
	sendspaceFileURLRegex = regexp.MustCompile(`^https?://(?:www\.)?sendspace\.com/file/([a-zA-Z0-9]+)/?$`)
)

type SendSpaceClient struct {
	*BaseClient
}

func NewSendSpaceClient(cfg ClientConfig) *SendSpaceClient {
	if cfg.UserAgent == "" {
		cfg.UserAgent = sendspaceUserAgent
	}
	return &SendSpaceClient{BaseClient: NewBaseClient(cfg)}
}

func (c *SendSpaceClient) Name() string {
	return "sendspace"
}

func (c *SendSpaceClient) Hosts() []string {
	return []string{"sendspace.com", "www.sendspace.com"}
}

func (c *SendSpaceClient) Resolve(ctx context.Context, inputURL, password string) (*TransferInfo, error) {
	fileID, err := c.parseURL(inputURL)
	if err != nil {
		return nil, err
	}

	directLink, fileName, fileSize, err := c.getFileInfo(ctx, fileID, password)
	if err != nil {
		return nil, err
	}

	return &TransferInfo{
		DirectURL: directLink,
		FileName:  fileName,
		FileSize:  fileSize,
		FileCount: 1,
	}, nil
}

func (c *SendSpaceClient) Stream(ctx context.Context, info *TransferInfo, w http.ResponseWriter) (int64, error) {
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

func (c *SendSpaceClient) parseURL(inputURL string) (string, error) {
	parsed, err := url.Parse(inputURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}

	host := strings.ToLower(parsed.Host)
	if host != "sendspace.com" && host != "www.sendspace.com" {
		return "", errors.New("domain not allowed: only sendspace.com is supported")
	}


	if matches := sendspaceFileURLRegex.FindStringSubmatch(inputURL); len(matches) == 2 {
		return matches[1], nil
	}

	return "", errors.New("unsupported SendSpace URL format (expected: sendspace.com/file/XXXX)")
}

type sendspaceFileResponse struct {
	DownloadURL string `json:"download_url"`
	FileName    string `json:"file_name"`
	FileSize    int64  `json:"file_size"`
	Error       string `json:"error"`
}

func (c *SendSpaceClient) getFileInfo(ctx context.Context, fileID, password string) (string, string, int64, error) {
	apiURL := sendspaceAPIBaseURL + "/file/" + fileID
	if password != "" {
		apiURL += "?password=" + url.QueryEscape(password)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return "", "", 0, err
	}
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", "", 0, fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	var result sendspaceFileResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", 0, fmt.Errorf("failed to parse API response: %w", err)
	}

	if result.Error != "" {
		if strings.Contains(strings.ToLower(result.Error), "password") {
			return "", "", 0, &PasswordRequiredError{}
		}
		return "", "", 0, fmt.Errorf("API error: %s", result.Error)
	}

	if result.DownloadURL == "" {
		return "", "", 0, errors.New("no download URL in API response")
	}

	return result.DownloadURL, result.FileName, result.FileSize, nil
}