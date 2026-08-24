package providers

import (
	"context"
	"errors"
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
	UserAgent      string
}

// BaseClient provides common HTTP client functionality.
type BaseClient struct {
	httpClient *http.Client
	userAgent  string
}

func NewBaseClient(cfg ClientConfig) *BaseClient {
	if cfg.UserAgent == "" {
		cfg.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	}
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
		userAgent: cfg.UserAgent,
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