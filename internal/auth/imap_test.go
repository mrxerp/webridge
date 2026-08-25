package auth

import (
	"testing"

	"webridge/internal/config"
)

func TestIMAPDomainAllowed(t *testing.T) {
	s := &Service{imapCfg: config.IMAPEmailConfig{AllowedDomains: []string{"Example.COM", " alt.org "}}}
	for _, ok := range []struct {
		email string
		want  bool
	}{
		{"bob@example.com", true},
		{"BOB@EXAMPLE.COM", true},
		{"a@alt.org", true},
		{"a@mail.example.com", false},
		{"a@evil.com", false},
		{"no-at-sign", false},
	} {
		if got := s.imapDomainAllowed(ok.email); got != ok.want {
			t.Errorf("imapDomainAllowed(%q) = %v, want %v", ok.email, got, ok.want)
		}
	}
}

func TestProvisionIMAP(t *testing.T) {
	s := New(&config.Config{
		Auth: config.AuthConfig{Users: []config.UserConfig{{Username: "admin", Password: "x", Role: "admin"}}},
		IMAP: config.IMAPEmailConfig{DefaultGroups: []string{"users"}},
	}, nil, "", "", "")

	if _, err := s.provisionIMAP("bob@example.com"); err == nil {
		t.Fatal("expected error when auto_provision is off")
	}

	s.imapCfg.AutoProvision = true
	u, err := s.provisionIMAP("bob@example.com")
	if err != nil || u.source != "imap" || u.role != "user" {
		t.Fatalf("provision = %+v, %v; want imap/user", u, err)
	}
	// idempotent on re-login
	u2, err := s.provisionIMAP("bob@example.com")
	if err != nil || u2.source != "imap" || u2.role != u.role || len(u2.groups) != len(u.groups) {
		t.Fatalf("re-provision changed user: %+v vs %+v (%v)", u2, u, err)
	}
}
