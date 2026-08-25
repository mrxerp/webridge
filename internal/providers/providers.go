package providers

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// TransferInfo contains the resolved download information.
type TransferInfo struct {
	DirectURL string
	FileName  string
	FileSize  int64
	FileCount int
}

// PasswordRequiredError indicates the transfer needs a password.
type PasswordRequiredError struct{}

func (e *PasswordRequiredError) Error() string {
	return "password required"
}

// Provider is the interface all file transfer services must implement.
type Provider interface {
	// Name returns the provider's canonical name (e.g., "wetransfer").
	Name() string

	// Hosts returns the list of domains this provider handles.
	Hosts() []string

	// Resolve fetches the direct download URL and metadata for a transfer.
	Resolve(ctx context.Context, url, password string) (*TransferInfo, error)

	// Stream downloads the file and writes it to the http.ResponseWriter.
	// Returns bytes written and error (nil on success or client disconnect).
	Stream(ctx context.Context, info *TransferInfo, w http.ResponseWriter) (int64, error)
}

// ClientConfig holds common HTTP client settings.
type ClientConfig struct {
	RequestTimeout time.Duration
	MaxRedirects   int
}

// BaseClient provides common HTTP client functionality.
type BaseClient struct {
	httpClient *http.Client
	userAgent  string
}

func NewBaseClient(cfg ClientConfig) *BaseClient {
	return &BaseClient{
		httpClient: &http.Client{
			Timeout: cfg.RequestTimeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= cfg.MaxRedirects {
					return ErrTooManyRedirects
				}
				return nil
			},
		},
		userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	}
}

// Stream downloads the file from info.DirectURL and writes it to w.
func (c *BaseClient) Stream(ctx context.Context, info *TransferInfo, w http.ResponseWriter) (int64, error) {
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

var ErrTooManyRedirects = &tooManyRedirectsError{}

type tooManyRedirectsError struct{}

func (e *tooManyRedirectsError) Error() string {
	return "too many redirects"
}

// IsClientDisconnect reports whether err is the client hanging up or
// cancelling, which is not a download failure.
func IsClientDisconnect(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) {
		return true
	}
	errStr := err.Error()
	return strings.Contains(errStr, "context canceled") ||
		strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "connection closed") ||
		strings.Contains(errStr, "use of closed network connection")
}

// IsFormatError reports whether the error indicates an invalid URL format
// for the provider (not an upstream API failure).
func IsFormatError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "unsupported") && strings.Contains(errStr, "url format") ||
		strings.Contains(errStr, "domain not allowed") ||
		strings.Contains(errStr, "invalid url")
}

// IsUpstreamError reports whether the error indicates a provider API failure
// (network, parsing, rate limit, etc.) rather than a client input error.
func IsUpstreamError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "api request failed") ||
		strings.Contains(errStr, "failed to parse api response") ||
		strings.Contains(errStr, "api error") ||
		strings.Contains(errStr, "no download url") ||
		strings.Contains(errStr, "no files in") ||
		strings.Contains(errStr, "context deadline") ||
		strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "upstream failed")
}