package auth

import (
	"crypto/tls"
	"fmt"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
)

// ldapAuth does search-then-bind: bind a service account (or anonymously),
// find the user's DN, then bind as that DN to verify the password.
func (s *Service) ldapAuth(username, password string) (bool, error) {
	s.mu.Lock()
	lc := s.ldapCfg
	s.mu.Unlock()
	scheme := "ldap"
	var opts []goldap.DialOpt
	tlsCfg := &tls.Config{ServerName: lc.Host, InsecureSkipVerify: lc.InsecureSkipVerify}
	if lc.Port == 636 {
		scheme = "ldaps"
		opts = append(opts, goldap.DialWithTLSConfig(tlsCfg))
	}
	conn, err := goldap.DialURL(fmt.Sprintf("%s://%s:%d", scheme, lc.Host, lc.Port), opts...)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	conn.SetTimeout(10 * time.Second)

	if lc.UseTLS && lc.Port != 636 {
		if err := conn.StartTLS(tlsCfg); err != nil {
			return false, err
		}
	}

	if err := conn.Bind(lc.BindDN, lc.BindPassword); err != nil {
		return false, fmt.Errorf("service bind: %w", err)
	}

	searchReq := goldap.NewSearchRequest(
		lc.BaseDN,
		goldap.ScopeWholeSubtree,
		goldap.NeverDerefAliases,
		1, 5, false,
		fmt.Sprintf(lc.UserFilter, goldap.EscapeFilter(username)),
		[]string{"dn"},
		nil,
	)
	sr, err := conn.Search(searchReq)
	if err != nil {
		return false, fmt.Errorf("search: %w", err)
	}
	if len(sr.Entries) != 1 {
		return false, fmt.Errorf("user not found or not unique in LDAP")
	}

	if err := conn.Bind(sr.Entries[0].DN, password); err != nil {
		return false, fmt.Errorf("user bind: %w", err)
	}
	return true, nil
}

// provisionLDAP JIT-registers an LDAP-authenticated user so admins can assign
// local groups/roles. No password is stored — logins always re-check LDAP.
func (s *Service) provisionLDAP(username string) user {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, exists := s.users[username]; exists && u.source == "ldap" {
		return u
	}
	u := user{
		role:   "user",
		source: "ldap",
		groups: append([]string{}, s.ldapCfg.DefaultGroups...),
	}
	s.users[username] = u
	return u
}
