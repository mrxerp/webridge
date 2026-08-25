package providers

import (
	"net/url"
	"strings"
	"sync"
)

type Registry struct {
	mu       sync.RWMutex
	providers map[string]Provider
	hostMap  map[string]Provider
}

func NewRegistry() *Registry {
	return &Registry{
		providers: make(map[string]Provider),
		hostMap:   make(map[string]Provider),
	}
}

func (r *Registry) Register(p Provider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers[p.Name()] = p
	for _, host := range p.Hosts() {
		r.hostMap[strings.ToLower(host)] = p
	}
}

func (r *Registry) GetProviderNames() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.providers))
	for _, p := range r.providers {
		names = append(names, p.Name())
	}
	return names
}

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

	if p, ok := r.hostMap[host]; ok {
		return p, nil
	}
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
	return "no provider found for this URL"
}
