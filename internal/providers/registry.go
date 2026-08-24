package providers

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// Registry holds all registered providers and resolves URLs to the correct one.
type Registry struct {
	mu         sync.RWMutex
	providers  map[string]Provider
	hostMap    map[string]Provider // host -> provider
}

func NewRegistry() *Registry {
	return &Registry{
		providers: make(map[string]Provider),
		hostMap:   make(map[string]Provider),
	}
}

// Register adds a provider to the registry.
func (r *Registry) Register(p Provider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers[p.Name()] = p
	for _, host := range p.Hosts() {
		r.hostMap[strings.ToLower(host)] = p
	}
}

// Get returns a provider by name.
func (r *Registry) Get(name string) (Provider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[name]
	return p, ok
}

// ResolveProvider finds the provider for a given URL.
func (r *Registry) ResolveProvider(rawURL string) (Provider, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	host := strings.ToLower(parsed.Host)
	host, _, _ = strings.Cut(host, ":")
	if strings.HasSuffix(host, ".") {
		host = host[:len(host)-1]
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	// Exact match first
	if p, ok := r.hostMap[host]; ok {
		return p, nil
	}

	// Subdomain match (e.g., sub.wetransfer.com)
	for h, p := range r.hostMap {
		if strings.HasSuffix(host, "."+h) {
			return p, nil
		}
	}

	return nil, ErrNoProvider
}

var ErrNoProvider = &noProviderError{}

type noProviderError struct{}

func (e *noProviderError) Error() string {
	return "no provider found for this URL; supported providers: wetransfer"
}

// ResolveAndStream is a convenience method that finds the provider and resolves the URL.
func (r *Registry) ResolveAndStream(ctx context.Context, rawURL, password string, w http.ResponseWriter) (Provider, *TransferInfo, int64, error) {
	p, err := r.ResolveProvider(rawURL)
	if err != nil {
		return nil, nil, 0, err
	}

	info, err := p.Resolve(ctx, rawURL, password)
	if err != nil {
		return p, nil, 0, err
	}

	n, err := p.Stream(ctx, info, w)
	return p, info, n, err
}