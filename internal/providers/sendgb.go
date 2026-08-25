package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

const (
	sendgbAPIBaseURL = "https://api.sendgb.com/api"
)

var (
	sendgbShortURLRegex = regexp.MustCompile(`^https?://(?:www\.)?sendgb\.com/(?:[a-z]{2}/download/)?([a-zA-Z0-9]+)/?$`)
	sendgbFileURLRegex  = regexp.MustCompile(`^https?://(?:www\.)?sendgb\.com/file/([a-zA-Z0-9]+)/?$`)
)

type SendGBClient struct {
	*BaseClient
}

func NewSendGBClient(cfg ClientConfig) *SendGBClient {
	return &SendGBClient{BaseClient: NewBaseClient(cfg)}
}

func (c *SendGBClient) Name() string {
	return "sendgb"
}

func (c *SendGBClient) Hosts() []string {
	return []string{"sendgb.com", "www.sendgb.com"}
}

func (c *SendGBClient) Resolve(ctx context.Context, inputURL, password string) (*TransferInfo, error) {
	code, err := c.parseURL(inputURL)
	if err != nil {
		return nil, err
	}

	info, err := c.getTransferInfo(ctx, code, password)
	if err != nil {
		return nil, err
	}

	directURL, err := c.getDownloadURL(ctx, code, info.FileKey, password)
	if err != nil {
		return nil, err
	}

	return &TransferInfo{
		DirectURL: directURL,
		FileName:  info.FileName,
		FileSize:  info.FileSize,
		FileCount: 1,
	}, nil
}

func (c *SendGBClient) parseURL(inputURL string) (string, error) {
	parsed, err := url.Parse(inputURL)
	if err != nil {
		return "", err
	}

	host := strings.ToLower(parsed.Host)
	if host != "sendgb.com" && !strings.HasSuffix(host, ".sendgb.com") {
		return "", errors.New("domain not allowed: only sendgb.com is supported")
	}

	if matches := sendgbShortURLRegex.FindStringSubmatch(inputURL); len(matches) == 2 {
		return matches[1], nil
	}

	if matches := sendgbFileURLRegex.FindStringSubmatch(inputURL); len(matches) == 2 {
		return matches[1], nil
	}

	return "", errors.New("unsupported SendGB URL format")
}

type sendgbTransferInfo struct {
	FileName string
	FileSize int64
	FileKey  string
}

type sendgbTransferResponse struct {
	OK        bool   `json:"ok"`
	Code      string `json:"code"`
	Message   string `json:"message"`
	TotalSize int64  `json:"total_size"`
	Files     []struct {
		Name string `json:"name"`
		Key  string `json:"key"`
		Size int64  `json:"size"`
	} `json:"files"`
}

func (c *SendGBClient) getTransferInfo(ctx context.Context, code, password string) (*sendgbTransferInfo, error) {
	apiURL := sendgbAPIBaseURL + "/download/" + code

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Language", "en")
	if password != "" {
		req.Header.Set("X-Transfer-Password", password)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result sendgbTransferResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if !result.OK {
		msg := strings.ToLower(result.Message)
		if strings.Contains(msg, "password") || result.Code == "incorrect_password" {
			return nil, &PasswordRequiredError{}
		}
		if result.Code == "not_found" {
			return nil, errors.New("transfer not found or expired")
		}
		return nil, errors.New(result.Message)
	}

	if len(result.Files) == 0 {
		return nil, errors.New("no files in transfer")
	}

	first := result.Files[0]
	return &sendgbTransferInfo{
		FileName: first.Name,
		FileSize: result.TotalSize,
		FileKey:  first.Key,
	}, nil
}

type sendgbWaybillResponse struct {
	OK           bool   `json:"ok"`
	SessionToken string `json:"session_token"`
}

type sendgbWaybillSegment struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type sendgbWaybillSegmentsResponse struct {
	OK       bool                   `json:"ok"`
	Segments []sendgbWaybillSegment `json:"segments"`
}

func (c *SendGBClient) getDownloadURL(ctx context.Context, code, fileKey, password string) (string, error) {
	waybillBody, _ := json.Marshal(map[string]any{
		"all":  "all",
		"keys": []string{fileKey},
	})

	sessionURL := sendgbAPIBaseURL + "/download/" + code + "/waybill-session"
	req, err := http.NewRequestWithContext(ctx, "POST", sessionURL, bytes.NewReader(waybillBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	if password != "" {
		req.Header.Set("X-Transfer-Password", password)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var sessionResp sendgbWaybillResponse
	if err := json.NewDecoder(resp.Body).Decode(&sessionResp); err != nil {
		return "", err
	}
	if !sessionResp.OK {
		return "", errors.New("waybill session failed")
	}

	segmentsURL := sendgbAPIBaseURL + "/download/waybill-session/" + sessionResp.SessionToken + "?ulid=" + code
	req2, err := http.NewRequestWithContext(ctx, "GET", segmentsURL, nil)
	if err != nil {
		return "", err
	}
	req2.Header.Set("User-Agent", c.userAgent)
	req2.Header.Set("Accept", "application/json")

	resp2, err := c.httpClient.Do(req2)
	if err != nil {
		return "", err
	}
	defer resp2.Body.Close()

	var segResp sendgbWaybillSegmentsResponse
	if err := json.NewDecoder(resp2.Body).Decode(&segResp); err != nil {
		return "", err
	}

	if !segResp.OK || len(segResp.Segments) == 0 {
		return "", errors.New("no download segments")
	}

	for _, seg := range segResp.Segments {
		if seg.Type == "DATA" && seg.URL != "" {
			return seg.URL, nil
		}
	}

	return "", errors.New("no download URL")
}
