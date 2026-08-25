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
	transferNowAPIBaseURL = "https://api.transfernow.net/api/v2"
)

var (
	transferNowShortURLRegex = regexp.MustCompile(`^https?://(?:www\.)?transfernow\.net/([a-zA-Z0-9]+)/?$`)
	transferNowFileURLRegex  = regexp.MustCompile(`^https?://(?:www\.)?transfernow\.net/dl/([a-zA-Z0-9]+)/?$`)
)

type TransferNowClient struct {
	*BaseClient
}

func NewTransferNowClient(cfg ClientConfig) *TransferNowClient {
	return &TransferNowClient{BaseClient: NewBaseClient(cfg)}
}

func (c *TransferNowClient) Name() string {
	return "transfernow"
}

func (c *TransferNowClient) Hosts() []string {
	return []string{"transfernow.net", "www.transfernow.net"}
}

func (c *TransferNowClient) Resolve(ctx context.Context, inputURL, password string) (*TransferInfo, error) {
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

func (c *TransferNowClient) parseURL(inputURL string) (string, error) {
	parsed, err := url.Parse(inputURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}

	host := strings.ToLower(parsed.Host)
	if host != "transfernow.net" && host != "www.transfernow.net" {
		return "", errors.New("domain not allowed: only transfernow.net is supported")
	}


	if matches := transferNowShortURLRegex.FindStringSubmatch(inputURL); len(matches) == 2 {
		return matches[1], nil
	}

	if matches := transferNowFileURLRegex.FindStringSubmatch(inputURL); len(matches) == 2 {
		return matches[1], nil
	}

	return "", errors.New("unsupported TransferNow URL format")
}

type transferNowTransferResponse struct {
	TransferID string `json:"transfer_id"`
	Files      []struct {
		Name string `json:"name"`
		Size int64  `json:"size"`
		URL  string `json:"url"`
	} `json:"files"`
	Error string `json:"error"`
}

func (c *TransferNowClient) getTransferInfo(ctx context.Context, transferID, password string) (string, string, int64, int, error) {
	apiURL := transferNowAPIBaseURL + "/transfers/" + transferID
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

	var result transferNowTransferResponse
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

	// Use the first file for the primary download
	firstFile := result.Files[0]
	var totalSize int64
	for _, f := range result.Files {
		totalSize += f.Size
	}

	return firstFile.URL, firstFile.Name, totalSize, len(result.Files), nil
}