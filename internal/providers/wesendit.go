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
	wesenditAPIBaseURL = "https://wesendit.com/api/v1"
)

var (
	wesenditShortURLRegex = regexp.MustCompile(`^https?://(?:www\.)?wesendit\.com/([a-zA-Z0-9]+)/?$`)
	wesenditFileURLRegex  = regexp.MustCompile(`^https?://(?:www\.)?wesendit\.com/d/([a-zA-Z0-9]+)/?$`)
)

type WesenditClient struct {
	*BaseClient
}

func NewWesenditClient(cfg ClientConfig) *WesenditClient {
	return &WesenditClient{BaseClient: NewBaseClient(cfg)}
}

func (c *WesenditClient) Name() string {
	return "wesendit"
}

func (c *WesenditClient) Hosts() []string {
	return []string{"wesendit.com", "www.wesendit.com"}
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