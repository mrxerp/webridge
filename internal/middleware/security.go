package middleware

import (
	"net"
	"net/http"
	"net/url"
	"strings"
)

func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'")
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		next.ServeHTTP(w, r)
	})
}

func ValidateURL(next http.Handler) http.Handler {
	allowedDomains := []string{
		"wetransfer.com",
		"we.tl",
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		urlParam := r.URL.Query().Get("url")
		if urlParam == "" {
			next.ServeHTTP(w, r)
			return
		}

		parsed, err := parseURL(urlParam)
		if err != nil {
			http.Error(w, "Invalid URL", http.StatusBadRequest)
			return
		}

		host := strings.ToLower(parsed.Host)
		allowed := false
		for _, d := range allowedDomains {
			if host == d || strings.HasSuffix(host, "."+d) {
				allowed = true
				break
			}
		}
		if !allowed {
			http.Error(w, "Domain not allowed", http.StatusForbidden)
			return
		}

		if isPrivateIP(host) {
			http.Error(w, "Private IP addresses not allowed", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func parseURL(rawURL string) (*url.URL, error) {
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}
	return url.Parse(rawURL)
}

func isPrivateIP(host string) bool {
	host = strings.Trim(host, "[]")
	host, _, _ = strings.Cut(host, ":")
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast())
}
