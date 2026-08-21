package audit

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Event struct {
	Time   time.Time `json:"time"`
	Action string    `json:"action"`
	User   string    `json:"user"`
	IP     string    `json:"ip"`
	Detail string    `json:"detail,omitempty"`
	URL    string    `json:"url,omitempty"`
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

	active     atomic.Int64
	completed  atomic.Int64
	failed     atomic.Int64
	bytes      atomic.Int64
	logins     atomic.Int64
	loginFails atomic.Int64
}

// ponytail: in-memory ring buffer, events lost on restart; persist to sqlite/file if history must survive restarts
func New(maxEvents int) *Log {
	if maxEvents <= 0 {
		maxEvents = 5000
	}
	return &Log{max: maxEvents}
}

func (l *Log) Add(action, user, ip, detail string) {
	l.AddEvent(Event{Time: time.Now(), Action: action, User: user, IP: ip, Detail: detail})
}

// AddEvent stores a fully populated event (e.g. downloads carrying their URL).
func (l *Log) AddEvent(e Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, e)
	if len(l.events) > l.max {
		l.events = l.events[len(l.events)-l.max:]
	}
}

type Query struct {
	Limit  int
	Action string
	User   string
	FromMs int64
	ToMs   int64
}

// Query returns up to Limit events, newest first, filtered by exact action,
// user substring, and [FromMs, ToMs] time window (unix millis; 0 = unbounded).
func (l *Log) Query(q Query) []Event {
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

// EndDownload is called exactly once per download request (via logDownload).
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

// WriteJSON is the shared JSON response writer for all packages.
func WriteJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	data, err := json.Marshal(v)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Write(data)
}
