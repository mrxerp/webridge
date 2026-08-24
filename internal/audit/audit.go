package audit

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Event struct {
	Time            time.Time `json:"time"`
	Action          string    `json:"action"`
	User            string    `json:"user"`
	IP              string    `json:"ip"`
	Detail          string    `json:"detail,omitempty"`
	URL             string    `json:"url,omitempty"`
	Provider        string    `json:"provider,omitempty"`
	Filename        string    `json:"filename,omitempty"`
	FileSize        int64     `json:"file_size,omitempty"`
	MimeType        string    `json:"mime_type,omitempty"`
	ResolvedURL     string    `json:"resolved_url,omitempty"`
	BytesTransferred int64    `json:"bytes_transferred,omitempty"`
	DurationMS      int64     `json:"duration_ms,omitempty"`
	SHA256          string    `json:"sha256,omitempty"`
	AnomalyFlags    []string  `json:"anomaly_flags,omitempty"`
	ClientUA        string    `json:"client_ua,omitempty"`
}

type Metrics struct {
	Active     int64  `json:"active_downloads"`
	Completed  int64  `json:"completed_downloads"`
	Failed     int64  `json:"failed_downloads"`
	Bytes      int64  `json:"bytes_transferred"`
	Logins     int64  `json:"logins"`
	LoginFails int64  `json:"failed_logins"`
	BytesHuman string `json:"bytes_human"`
}

type Log struct {
	mu     sync.Mutex
	events []Event
	max    int

	store *Store
	cfg   AnomalyConfig

	active     atomic.Int64
	completed  atomic.Int64
	failed     atomic.Int64
	bytes      atomic.Int64
	logins     atomic.Int64
	loginFails atomic.Int64
}

type AnomalyConfig struct {
	OffHoursStart      int
	OffHoursEnd        int
	BulkDownloadCount  int
	BulkDownloadWindow int // minutes
	MaxFileSizeGB      int
}

func New(maxEvents int) *Log {
	if maxEvents <= 0 {
		maxEvents = 5000
	}
	return &Log{max: maxEvents}
}

// NewWithStore creates a Log backed by a persistent SQLite store.
func NewWithStore(maxEvents int, store *Store) *Log {
	l := New(maxEvents)
	l.store = store
	return l
}

// SetAnomalyConfig enables anomaly flag computation on events.
func (l *Log) SetAnomalyConfig(cfg AnomalyConfig) {
	l.cfg = cfg
}

func (l *Log) Add(action, user, ip, detail string) {
	l.AddEvent(Event{Time: time.Now(), Action: action, User: user, IP: ip, Detail: detail})
}

func (l *Log) AddEvent(e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}

	// Compute anomaly flags if config is set
	if l.cfg.BulkDownloadCount > 0 {
		e.AnomalyFlags = l.detectAnomalies(e)
	}

	// Always keep in-memory ring for fast Metrics() and backward compat
	l.mu.Lock()
	l.events = append(l.events, e)
	if len(l.events) > l.max {
		l.events = l.events[len(l.events)-l.max:]
	}
	l.mu.Unlock()

	// Persist to SQLite if store is available
	if l.store != nil {
		l.store.enqueue(e)
	}
}

func (l *Log) detectAnomalies(e Event) []string {
	if e.Action != "download_success" && e.Action != "download_error" {
		return nil
	}
	var flags []string

	// Off-hours check
	if l.cfg.OffHoursStart > 0 && l.cfg.OffHoursEnd > 0 {
		hour := e.Time.Hour()
		if l.cfg.OffHoursStart > l.cfg.OffHoursEnd {
			if hour >= l.cfg.OffHoursStart || hour < l.cfg.OffHoursEnd {
				flags = append(flags, "off_hours")
			}
		} else {
			if hour >= l.cfg.OffHoursStart && hour < l.cfg.OffHoursEnd {
				flags = append(flags, "off_hours")
			}
		}
	}

	// Bulk download check
	if l.cfg.BulkDownloadCount > 0 && l.cfg.BulkDownloadWindow > 0 {
		window := time.Duration(l.cfg.BulkDownloadWindow) * time.Minute
		cutoff := e.Time.Add(-window)
		l.mu.Lock()
		count := 0
		for i := len(l.events) - 1; i >= 0; i-- {
			if l.events[i].Time.Before(cutoff) {
				break
			}
			if l.events[i].User == e.User && (l.events[i].Action == "download_success" || l.events[i].Action == "download_error") {
				count++
			}
		}
		l.mu.Unlock()
		if count >= l.cfg.BulkDownloadCount {
			flags = append(flags, "bulk_download")
		}
	}

	// Large file check
	if l.cfg.MaxFileSizeGB > 0 && e.FileSize > int64(l.cfg.MaxFileSizeGB)*1024*1024*1024 {
		flags = append(flags, "large_file")
	}

	return flags
}

type Query struct {
	Limit  int
	Action string
	User   string
	FromMs int64
	ToMs   int64
}

func (l *Log) Query(q Query) []Event {
	if l.store != nil {
		return l.store.Query(q)
	}
	return l.queryMemory(q)
}

func (l *Log) queryMemory(q Query) []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	limit := q.Limit
	if limit <= 0 || limit > len(l.events) {
		limit = len(l.events)
	}
	out := make([]Event, 0, limit)
	for i := len(l.events) - 1; i >= 0 && len(out) < limit; i-- {
		e := l.events[i]
		if q.Action != "" && e.Action != q.Action {
			continue
		}
		if q.User != "" && !strings.Contains(strings.ToLower(e.User), strings.ToLower(q.User)) {
			continue
		}
		ms := e.Time.UnixMilli()
		if q.FromMs > 0 && ms < q.FromMs {
			continue
		}
		if q.ToMs > 0 && ms > q.ToMs {
			continue
		}
		out = append(out, e)
	}
	return out
}

func (l *Log) StartDownload() { l.active.Add(1) }

func (l *Log) EndDownload(ok bool, bytes int64) {
	l.active.Add(-1)
	if ok {
		l.completed.Add(1)
		l.bytes.Add(bytes)
	} else {
		l.failed.Add(1)
	}
}

func (l *Log) Login(ok bool) {
	if ok {
		l.logins.Add(1)
	} else {
		l.loginFails.Add(1)
	}
}

func (l *Log) Snapshot() Metrics {
	return Metrics{
		Active:     l.active.Load(),
		Completed:  l.completed.Load(),
		Failed:     l.failed.Load(),
		Bytes:      l.bytes.Load(),
		Logins:     l.logins.Load(),
		LoginFails: l.loginFails.Load(),
		BytesHuman: FormatBytes(l.bytes.Load()),
	}
}

func (l *Log) MetricsHandler(w http.ResponseWriter, r *http.Request) {
	WriteJSON(w, l.Snapshot())
}

func (l *Log) EventsHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	fromMs, _ := strconv.ParseInt(q.Get("from"), 10, 64)
	toMs, _ := strconv.ParseInt(q.Get("to"), 10, 64)
	WriteJSON(w, map[string]any{"events": l.Query(Query{
		Limit:  limit,
		Action: q.Get("action"),
		User:   q.Get("user"),
		FromMs: fromMs,
		ToMs:   toMs,
	})})
}

// LogClientEvent handles POST /api/v1/audit/log from the frontend.
func (l *Log) LogClientEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Action string `json:"action"`
		Detail string `json:"detail"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	l.AddEvent(Event{
		Action: body.Action,
		Detail: body.Detail,
		IP:     r.RemoteAddr,
		ClientUA: r.UserAgent(),
	})
	w.WriteHeader(http.StatusNoContent)
}

// ExportCSVHandler streams audit events as a CSV file.
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
	enc.Write([]string{"time", "action", "user", "ip", "detail", "url", "provider", "filename", "file_size", "mime_type", "resolved_url", "bytes_transferred", "duration_ms", "sha256", "anomaly_flags", "client_ua"})
	for _, e := range events {
		flags, _ := json.Marshal(e.AnomalyFlags)
		enc.Write([]string{
			e.Time.Format(time.RFC3339),
			e.Action, e.User, e.IP, e.Detail, e.URL,
			e.Provider, e.Filename, strconv.FormatInt(e.FileSize, 10), e.MimeType,
			e.ResolvedURL, strconv.FormatInt(e.BytesTransferred, 10),
			strconv.FormatInt(e.DurationMS, 10), e.SHA256, string(flags), e.ClientUA,
		})
	}
	enc.Flush()
}

func parseQueryInt64(s string) int64 {
	v, _ := strconv.ParseInt(s, 10, 64)
	return v
}

func FormatBytes(b int64) string {
	if b <= 0 {
		return "0 B"
	}
	const unit = 1024
	if b < unit {
		return strconv.FormatInt(b, 10) + " B"
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return strconv.FormatFloat(float64(b)/float64(div), 'f', 1, 64) + " " + string("KMGTPE"[exp]) + "B"
}

func WriteJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	data, err := json.Marshal(v)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Write(data)
}
