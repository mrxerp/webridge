package audit

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type Event struct {
	Time             time.Time `json:"time"`
	Action           string    `json:"action"`
	User             string    `json:"user"`
	IP               string    `json:"ip"`
	Detail           string    `json:"detail,omitempty"`
	URL              string    `json:"url,omitempty"`
	Provider         string    `json:"provider,omitempty"`
	Filename         string    `json:"filename,omitempty"`
	FileSize         int64     `json:"file_size,omitempty"`
	ResolvedURL      string    `json:"resolved_url,omitempty"`
	BytesTransferred int64     `json:"bytes_transferred,omitempty"`
	DurationMS       int64     `json:"duration_ms,omitempty"`
	SHA256           string    `json:"sha256,omitempty"`
	ClientUA         string    `json:"client_ua,omitempty"`
}

type Metrics struct {
	Logins     int64 `json:"logins"`
	LoginFails int64 `json:"failed_logins"`
}

type Log struct {
	mu     sync.Mutex
	events []Event
	max    int

	store *Store

	logins     atomic.Int64
	loginFails atomic.Int64
}

func NewWithStore(maxEvents int, store *Store) *Log {
	if maxEvents <= 0 {
		maxEvents = 5000
	}
	return &Log{max: maxEvents, store: store}
}

func (l *Log) Add(action, user, ip, detail string) {
	l.AddEvent(Event{Time: time.Now(), Action: action, User: user, IP: ip, Detail: detail})
}

func (l *Log) AddEvent(e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	switch e.Action {
	case "login":
		l.logins.Add(1)
	case "login_failed":
		l.loginFails.Add(1)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, e)
	if len(l.events) > l.max {
		l.events = l.events[len(l.events)-l.max:]
	}
	if l.store != nil {
		l.store.enqueue(e)
	}
}

type Query struct {
	User     string
	Action   string
	Limit    int
	Offset   int
	FromMs   int64
	ToMs     int64
}

func (l *Log) Query(q Query) []Event {
	if l.store != nil {
		return l.store.Query(q)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Event, 0, len(l.events))
	for i := len(l.events) - 1; i >= 0; i-- {
		e := l.events[i]
		if q.User != "" && e.User != q.User {
			continue
		}
		if q.Action != "" && e.Action != q.Action {
			continue
		}
		out = append(out, e)
		if q.Limit > 0 && len(out) >= q.Limit {
			break
		}
	}
	return out
}

func (l *Log) Count(q Query) int64 {
	if l.store == nil {
		return 0
	}
	return l.store.Count(q)
}

func (l *Log) GetMetrics() Metrics {
	return Metrics{
		Logins:     l.logins.Load(),
		LoginFails: l.loginFails.Load(),
	}
}

// MetricsHandler returns current login metrics.
func (l *Log) MetricsHandler(w http.ResponseWriter, r *http.Request) {
	WriteJSON(w, l.GetMetrics())
}

// Login records a login attempt.
func (l *Log) Login(ok bool) {
	if ok {
		l.logins.Add(1)
	} else {
		l.loginFails.Add(1)
	}
}

func (l *Log) EventsHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	query := Query{
		Limit:  limit,
		Offset: offset,
		Action: q.Get("action"),
		User:   q.Get("user"),
		FromMs: parseQueryInt64(q.Get("from")),
		ToMs:   parseQueryInt64(q.Get("to")),
	}
	resp := map[string]any{"events": l.Query(query)}
	if q.Get("include_count") != "" {
		resp["total"] = l.Count(query)
	}
	WriteJSON(w, resp)
}

// LogClientEvent handles POST /api/v1/audit/log from the frontend.
func (l *Log) LogClientEvent(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Action string `json:"action"`
		Detail string `json:"detail"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	l.AddEvent(Event{
		Action:   body.Action,
		Detail:   body.Detail,
		IP:       r.RemoteAddr,
		ClientUA: r.UserAgent(),
	})
	w.WriteHeader(http.StatusNoContent)
}

func (l *Log) ExportCSVHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	events := l.Query(Query{
		Limit:  10000,
		Action: q.Get("action"),
		User:   q.Get("user"),
		FromMs: parseQueryInt64(q.Get("from")),
		ToMs:   parseQueryInt64(q.Get("to")),
	})

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=\"audit-export.csv\"")

	enc := csv.NewWriter(w)
	enc.Write([]string{"time", "action", "user", "ip", "detail", "url", "provider", "filename", "file_size", "resolved_url", "bytes_transferred", "duration_ms", "sha256", "client_ua"})
	for _, e := range events {
		enc.Write([]string{
			e.Time.Format(time.RFC3339),
			e.Action, e.User, e.IP, e.Detail, e.URL,
			e.Provider, e.Filename, strconv.FormatInt(e.FileSize, 10),
			e.ResolvedURL, strconv.FormatInt(e.BytesTransferred, 10),
			strconv.FormatInt(e.DurationMS, 10), e.SHA256, e.ClientUA,
		})
	}
	enc.Flush()
}

func parseQueryInt64(s string) int64 {
	v, _ := strconv.ParseInt(s, 10, 64)
	return v
}

func WriteJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func FormatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return strconv.FormatInt(b, 10) + " B"
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return strconv.FormatFloat(float64(b)/float64(div), 'f', 1, 64) + " KMGTPE"[exp:exp+1]
}
