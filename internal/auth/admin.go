package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"webridge/internal/audit"
	"webridge/internal/config"
	"webridge/internal/middleware"
)

type publicUser struct {
	Username string   `json:"username"`
	Role     string   `json:"role"`
	Groups   []string `json:"groups"`
	Source   string   `json:"source"`
}

type publicGroup struct {
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
}

func (s *Service) ListUsers(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	out := make([]publicUser, 0, len(s.users))
	for name, u := range s.users {
		src := u.source
		if src == "" {
			src = "local"
		}
		out = append(out, publicUser{Username: name, Role: u.role, Groups: u.groups, Source: src})
	}
	s.mu.Unlock()
	audit.WriteJSON(w, map[string]any{"users": out})
}

// LDAPStatus returns the full runtime LDAP config, minus the bind password.
func (s *Service) LDAPStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	lc := s.ldapCfg
	s.mu.Unlock()
	lc.BindPassword = ""
	audit.WriteJSON(w, lc)
}

// UpdateLDAP replaces the runtime LDAP config and persists it to the override
// file. Empty bind_password keeps the stored one.
func (s *Service) UpdateLDAP(auditLog *audit.Log) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req config.LDAPConfig
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		if req.Enabled && (req.Host == "" || req.BaseDN == "") {
			http.Error(w, "host and base_dn are required when enabled", http.StatusBadRequest)
			return
		}
		if req.Port == 0 {
			req.Port = 389
		}
		if req.UserFilter == "" {
			req.UserFilter = "(uid=%s)"
		}
		if req.DefaultGroups == nil {
			req.DefaultGroups = []string{"users"}
		}

		s.mu.Lock()
		if req.BindPassword == "" {
			req.BindPassword = s.ldapCfg.BindPassword
		}
		s.ldapCfg = req
		err := s.saveLDAP()
		s.mu.Unlock()
		if err != nil {
			http.Error(w, "saved for this session, but could not persist: "+err.Error(), http.StatusInternalServerError)
			return
		}

		auditLog.Add("ldap_updated", by(r), middleware.ClientIP(r), fmt.Sprintf("enabled=%v host=%s", req.Enabled, req.Host))
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Service) CreateUser(auditLog *audit.Log) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Role     string `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil ||
			req.Username == "" || req.Password == "" || (req.Role != "admin" && req.Role != "user") {
			http.Error(w, "username, password and role (admin|user) required", http.StatusBadRequest)
			return
		}

		s.mu.Lock()
		if _, exists := s.users[req.Username]; exists {
			s.mu.Unlock()
			http.Error(w, "User already exists", http.StatusConflict)
			return
		}
		hash, salt := hashPassword(req.Password)
		groups := []string{}
		if req.Role != "admin" {
			groups = append(groups, "users")
		}
		s.users[req.Username] = user{hash: hash, salt: salt, role: req.Role, groups: groups}
		s.mu.Unlock()

		auditLog.Add("user_created", req.Username, middleware.ClientIP(r), "role="+req.Role)
		s.logger.Info("user created", "username", req.Username, "role", req.Role, "by", by(r))
		w.WriteHeader(http.StatusCreated)
	}
}

func (s *Service) UpdateUser(auditLog *audit.Log) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("username")
		var req struct {
			Role     *string   `json:"role"`
			Password *string   `json:"password"`
			Groups   *[]string `json:"groups"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		if req.Role != nil && *req.Role != "admin" && *req.Role != "user" {
			http.Error(w, "role must be admin or user", http.StatusBadRequest)
			return
		}

		s.mu.Lock()
		u, ok := s.users[name]
		if !ok {
			s.mu.Unlock()
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		if u.source == "ldap" && req.Password != nil && *req.Password != "" {
			s.mu.Unlock()
			http.Error(w, "Cannot set password for LDAP users — they authenticate via LDAP", http.StatusBadRequest)
			return
		}
		if req.Groups != nil {
			for _, g := range *req.Groups {
				if _, ok := s.groups[g]; !ok {
					s.mu.Unlock()
					http.Error(w, "Unknown group: "+g, http.StatusBadRequest)
					return
				}
			}
		}
		if req.Role != nil && u.role == "admin" && *req.Role != "admin" && s.adminCount() <= 1 {
			s.mu.Unlock()
			http.Error(w, "Cannot demote the last admin", http.StatusConflict)
			return
		}
		if req.Role != nil {
			u.role = *req.Role
		}
		if req.Password != nil && *req.Password != "" {
			u.hash, u.salt = hashPassword(*req.Password)
		}
		if req.Groups != nil {
			u.groups = *req.Groups
		}
		s.users[name] = u
		s.mu.Unlock()

		auditLog.Add("user_updated", name, middleware.ClientIP(r), updateDetail(req.Role, req.Password, req.Groups))
		s.logger.Info("user updated", "username", name, "by", by(r))
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Service) DeleteUser(auditLog *audit.Log) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("username")

		s.mu.Lock()
		u, ok := s.users[name]
		if !ok {
			s.mu.Unlock()
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		if u.role == "admin" && s.adminCount() <= 1 {
			s.mu.Unlock()
			http.Error(w, "Cannot delete the last admin", http.StatusConflict)
			return
		}
		delete(s.users, name)
		for tok, sess := range s.sessions {
			if sess.username == name {
				delete(s.sessions, tok)
			}
		}
		s.mu.Unlock()

		auditLog.Add("user_deleted", name, middleware.ClientIP(r), "")
		s.logger.Info("user deleted", "username", name, "by", by(r))
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Service) ListGroups(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	out := make([]publicGroup, 0, len(s.groups))
	for name, g := range s.groups {
		out = append(out, publicGroup{Name: name, Permissions: g.permissions})
	}
	s.mu.Unlock()
	audit.WriteJSON(w, map[string]any{"groups": out})
}

func (s *Service) CreateGroup(auditLog *audit.Log) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Name        string   `json:"name"`
			Permissions []string `json:"permissions"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
			http.Error(w, "group name required", http.StatusBadRequest)
			return
		}
		perms, err := normalizePerms(req.Permissions)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		s.mu.Lock()
		if _, exists := s.groups[req.Name]; exists {
			s.mu.Unlock()
			http.Error(w, "Group already exists", http.StatusConflict)
			return
		}
		s.groups[req.Name] = group{permissions: perms}
		s.mu.Unlock()

		auditLog.Add("group_created", by(r), middleware.ClientIP(r), req.Name)
		s.logger.Info("group created", "group", req.Name, "by", by(r))
		w.WriteHeader(http.StatusCreated)
	}
}

func (s *Service) UpdateGroup(auditLog *audit.Log) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		var req struct {
			Permissions []string `json:"permissions"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		perms, err := normalizePerms(req.Permissions)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		s.mu.Lock()
		if _, ok := s.groups[name]; !ok {
			s.mu.Unlock()
			http.Error(w, "Group not found", http.StatusNotFound)
			return
		}
		s.groups[name] = group{permissions: perms}
		s.mu.Unlock()

		auditLog.Add("group_updated", by(r), middleware.ClientIP(r), name)
		s.logger.Info("group updated", "group", name, "by", by(r))
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Service) DeleteGroup(auditLog *audit.Log) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")

		s.mu.Lock()
		if _, ok := s.groups[name]; !ok {
			s.mu.Unlock()
			http.Error(w, "Group not found", http.StatusNotFound)
			return
		}
		delete(s.groups, name)
		for uname, u := range s.users {
			filtered := u.groups[:0]
			for _, g := range u.groups {
				if g != name {
					filtered = append(filtered, g)
				}
			}
			u.groups = filtered
			s.users[uname] = u
		}
		s.mu.Unlock()

		auditLog.Add("group_deleted", by(r), middleware.ClientIP(r), name)
		s.logger.Info("group deleted", "group", name, "by", by(r))
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Service) saveLDAP() error {
	if s.ldapFile == "" {
		return nil
	}
	data, err := json.Marshal(s.ldapCfg)
	if err != nil {
		return err
	}
	return os.WriteFile(s.ldapFile, data, 0o600)
}

func normalizePerms(perms []string) ([]string, error) {
	valid := map[string]bool{}
	for _, p := range ValidPerms {
		valid[p] = true
	}
	out := make([]string, 0, len(perms))
	seen := map[string]bool{}
	for _, p := range perms {
		if !valid[p] {
			return nil, errInvalidPerm(p)
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out, nil
}

type permError string

func (e permError) Error() string { return "Unknown permission: " + string(e) }

func errInvalidPerm(p string) error { return permError(p) }

func (s *Service) adminCount() int {
	n := 0
	for _, u := range s.users {
		if u.role == "admin" {
			n++
		}
	}
	return n
}

func by(r *http.Request) string { return Username(r.Context()) }

func updateDetail(role *string, password *string, groups *[]string) string {
	detail := ""
	if role != nil {
		detail += "role=" + *role + " "
	}
	if password != nil {
		detail += "password=changed "
	}
	if groups != nil {
		detail += "groups=updated"
	}
	return detail
}
