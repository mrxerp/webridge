package auth

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"

	"webridge/internal/config"
)

var errPendingApproval = errors.New("email sign-in is not approved yet; ask an administrator to enable your account")

// imapAuth verifies credentials by logging into the org's IMAP server.
// A NO reply to LOGIN means bad credentials (false, nil); transport problems
// return an error.
func (s *Service) imapAuth(email, password string) (bool, error) {
	s.mu.Lock()
	ic := s.imapCfg
	s.mu.Unlock()

	addr := fmt.Sprintf("%s:%d", ic.Host, ic.Port)
	opts := &imapclient.Options{
		TLSConfig: &tls.Config{ServerName: ic.Host, InsecureSkipVerify: ic.InsecureSkipVerify},
		Dialer:    &net.Dialer{Timeout: 10 * time.Second},
	}

	var (
		c   *imapclient.Client
		err error
	)
	// Port 993 = IMAPS (direct TLS), always use DialTLS regardless of UseStartTLS
	// Port 143 with UseStartTLS = upgrade from plain
	// Otherwise fallback to DialTLS (covers custom TLS ports)
	if ic.Port == 143 && ic.UseStartTLS {
		c, err = imapclient.DialStartTLS(addr, opts)
	} else {
		c, err = imapclient.DialTLS(addr, opts)
	}
	if err != nil {
		return false, err
	}
	defer c.Close()

	if err := c.Login(email, password).Wait(); err != nil {
		return false, nil
	}
	c.Logout()
	return true, nil
}

// imapDomainAllowed reports whether the email's domain is on the allowlist.
func (s *Service) imapDomainAllowed(email string) bool {
	s.mu.Lock()
	domains := s.imapCfg.AllowedDomains
	s.mu.Unlock()

	at := strings.LastIndex(email, "@")
	if at < 0 {
		return false
	}
	dom := strings.ToLower(email[at+1:])
	for _, d := range domains {
		if strings.EqualFold(strings.TrimSpace(d), dom) {
			return true
		}
	}
	return false
}

// provisionIMAP JIT-registers an IMAP-authenticated org user so admins can
// assign local groups/roles. No password is stored — logins always re-check
// IMAP. Returns an error when auto-provisioning is disabled.
func (s *Service) provisionIMAP(email string) (user, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, exists := s.users[email]; exists && u.source == "imap" {
		return u, nil
	}
	if !s.imapCfg.AutoProvision {
		return user{}, errPendingApproval
	}
	u := user{
		role:   "user",
		source: "imap",
		groups: append([]string{}, s.imapCfg.DefaultGroups...),
	}
	s.users[email] = u
	return u, nil
}

func normalizeIMAP(cfg config.IMAPEmailConfig) config.IMAPEmailConfig {
	if cfg.Port == 0 {
		cfg.Port = 993
	}
	out := cfg.AllowedDomains[:0]
	for _, d := range cfg.AllowedDomains {
		if d = strings.ToLower(strings.TrimSpace(d)); d != "" {
			out = append(out, d)
		}
	}
	cfg.AllowedDomains = out
	groups := cfg.DefaultGroups[:0]
	for _, g := range cfg.DefaultGroups {
		if g = strings.TrimSpace(g); g != "" {
			groups = append(groups, g)
		}
	}
	if groups == nil {
		groups = []string{"users"}
	}
	cfg.DefaultGroups = groups
	return cfg
}
