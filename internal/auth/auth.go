package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"webridge/internal/audit"
	"webridge/internal/config"
	"webridge/internal/middleware"
)

const cookieName = "pd_session"

var ValidPerms = []string{"download", "dashboard", "audit", "users", "groups"}

type user struct {
	hash   []byte
	salt   []byte
	role   string
	groups []string
	source string // "local" or "ldap"
}

type group struct {
	permissions []string
}

type session struct {
	username string
	role     string
	expires  time.Time
}

type ctxKey int

const (
	ctxUser ctxKey = iota
	ctxRole
)

type Service struct {
	users    map[string]user
	groups   map[string]group
	mu       sync.Mutex
	sessions map[string]session
	ttl      time.Duration
	logger   *slog.Logger
	ldapCfg  config.LDAPConfig // guarded by mu
	ldapFile string
}

// ponytail: SHA-256+salt instead of bcrypt to avoid a new dep; fine for a small self-hosted tool, swap for golang.org/x/crypto/bcrypt if this ever faces real attackers
// ldapFile: JSON overrides edited from the admin UI; empty path disables persistence.
func New(cfg *config.Config, logger *slog.Logger, ldapFile string) *Service {
	authCfg := cfg.Auth
	ttl := time.Duration(authCfg.SessionTTL)
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	s := &Service{
		users: make(map[string]user, len(authCfg.Users)),
		groups: map[string]group{
			"users": {permissions: []string{"download"}},
			"admin": {permissions: append([]string(nil), ValidPerms...)},
		},
		sessions: make(map[string]session),
		ttl:      ttl,
		logger:   logger,
		ldapCfg:  cfg.LDAP,
		ldapFile: ldapFile,
	}
	if data, err := os.ReadFile(ldapFile); err == nil {
		var ov config.LDAPConfig
		if json.Unmarshal(data, &ov) == nil {
			s.ldapCfg = ov
		}
	}
	for _, u := range authCfg.Users {
		if u.Username == "" || u.Password == "" {
			continue
		}
		role := u.Role
		if role != "admin" {
			role = "user"
		}
		hash, salt := hashPassword(u.Password)
		groups := []string{}
		if role != "admin" {
			groups = append(groups, "users")
		}
		s.users[u.Username] = user{hash: hash, salt: salt, role: role, groups: groups, source: "local"}
	}

	return s
}

func hashPassword(pw string) (hash, salt []byte) {
	salt = make([]byte, 16)
	rand.Read(salt)
	h := sha256.Sum256(append(salt, pw...))
	return h[:], salt
}

// verify checks local credentials. exists distinguishes "known local user with
// wrong password" from "unknown user" — LDAP fallback only applies to the latter.
func (s *Service) verify(username, password string) (u user, exists, ok bool) {
	u, exists = s.users[username]
	if !exists {
		// burn comparable time so unknown users aren't distinguishable by timing
		u = user{hash: make([]byte, 32), salt: make([]byte, 16)}
		sha256.Sum256(append(u.salt, password...))
		return u, false, false
	}
	if len(u.hash) == 0 { // LDAP-sourced user: no local credential
		return u, true, false
	}
	h := sha256.Sum256(append(u.salt, password...))
	return u, true, subtle.ConstantTimeCompare(h[:], u.hash) == 1
}

// effectivePerms: admins get everything; everyone else gets the union of their groups' permissions.
func (s *Service) effectivePerms(username string) map[string]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	perms := map[string]bool{}
	u, ok := s.users[username]
	if !ok {
		return perms
	}
	if u.role == "admin" {
		for _, p := range ValidPerms {
			perms[p] = true
		}
		return perms
	}
	for _, g := range u.groups {
		if grp, ok := s.groups[g]; ok {
			for _, p := range grp.permissions {
				perms[p] = true
			}
		}
	}
	return perms
}

func (s *Service) permsList(username string) []string {
	m := s.effectivePerms(username)
	out := make([]string, 0, len(m))
	for _, p := range ValidPerms {
		if m[p] {
			out = append(out, p)
		}
	}
	return out
}

func (s *Service) Login(auditLog *audit.Log) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" || req.Password == "" {
			http.Error(w, "username and password required", http.StatusBadRequest)
			return
		}

		ip := middleware.ClientIP(r)
		u, exists, ok := s.verify(req.Username, req.Password)
		viaLDAP := false
		s.mu.Lock()
		ldapEnabled := s.ldapCfg.Enabled
		s.mu.Unlock()
		if !ok && !exists && ldapEnabled {
			if lok, lerr := s.ldapAuth(req.Username, req.Password); lok {
				viaLDAP = true
				u = s.provisionLDAP(req.Username)
				ok = true
			} else if lerr != nil {
				s.logger.Warn("ldap auth failed", "username", req.Username, "error", lerr)
			}
		}
		auditLog.Login(ok)
		if !ok {
			auditLog.Add("login_failed", req.Username, ip, "")
			s.logger.Warn("login failed", "username", req.Username, "ip", ip)
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		tok := make([]byte, 32)
		rand.Read(tok)
		token := hex.EncodeToString(tok)

		s.mu.Lock()
		s.sessions[token] = session{username: req.Username, role: u.role, expires: time.Now().Add(s.ttl)}
		s.mu.Unlock()

		auditLog.Add("login_success", req.Username, ip, map[bool]string{true: "ldap", false: "local"}[viaLDAP])
		s.logger.Info("login", "username", req.Username, "ip", ip, "source", map[bool]string{true: "ldap", false: "local"}[viaLDAP])

		http.SetCookie(w, &http.Cookie{
			Name:     cookieName,
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   int(s.ttl.Seconds()),
		})
		audit.WriteJSON(w, map[string]any{"username": req.Username, "role": u.role, "permissions": s.permsList(req.Username)})
	}
}

func (s *Service) Logout(auditLog *audit.Log) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(cookieName); err == nil {
			s.mu.Lock()
			sess, existed := s.sessions[c.Value]
			delete(s.sessions, c.Value)
			s.mu.Unlock()
			if existed {
				auditLog.Add("logout", sess.username, middleware.ClientIP(r), "")
			}
		}
		http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1})
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Service) Me(w http.ResponseWriter, r *http.Request) {
	username, _ := r.Context().Value(ctxUser).(string)
	role, _ := r.Context().Value(ctxRole).(string)
	audit.WriteJSON(w, map[string]any{
		"authenticated": username != "",
		"username":      username,
		"role":          role,
		"permissions":   s.permsList(username),
	})
}

func (s *Service) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		if err != nil {
			unauthorized(w)
			return
		}
		s.mu.Lock()
		sess, ok := s.sessions[c.Value]
		if ok && time.Now().After(sess.expires) {
			delete(s.sessions, c.Value)
			ok = false
		}
		s.mu.Unlock()
		if !ok {
			unauthorized(w)
			return
		}
		ctx := context.WithValue(r.Context(), ctxUser, sess.username)
		ctx = context.WithValue(ctx, ctxRole, sess.role)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequirePerm must run after RequireAuth; checks the user's effective permissions.
func (s *Service) RequirePerm(perm string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			username, _ := r.Context().Value(ctxUser).(string)
			if !s.effectivePerms(username)[perm] {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func unauthorized(w http.ResponseWriter) {
	w.WriteHeader(http.StatusUnauthorized)
	audit.WriteJSON(w, map[string]string{"error": "unauthorized"})
}

// Username returns the authenticated username from context ("" if anonymous).
func Username(ctx context.Context) string {
	u, _ := ctx.Value(ctxUser).(string)
	return u
}
