package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

const (
	sendspaceAPIBaseURL = "https://www.sendspace.com/api"
)

var (
	sendspaceFileURLRegex = regexp.MustCompile(`^https?://(?:www\.)?sendspace\.com/file/([a-zA-Z0-9]+)/?$`)
)

type SendSpaceClient struct {
	*BaseClient
}

func NewSendSpaceClient(cfg ClientConfig) *SendSpaceClient {
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