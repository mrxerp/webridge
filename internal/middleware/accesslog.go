package middleware

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type accessEntry struct {
	Time      string `json:"time"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Status    int    `json:"status"`
	Duration  int64  `json:"duration_ms"`
	IP        string `json:"ip"`
	Bytes     int64  `json:"bytes_sent"`
	UserAgent string `json:"user_agent"`
}

// AccessLog returns middleware that appends one JSON line per request to a daily-rotated JSONL file.
func AccessLog(dir string, logger *slog.Logger) func(http.Handler) http.Handler {
	if dir == "" {
		return func(next http.Handler) http.Handler { return next }
	}
	w := &jsonlWriter{dir: dir, logger: logger}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := &responseWriter{ResponseWriter: rw, statusCode: http.StatusOK}
			next.ServeHTTP(ww, r)
			w.write(accessEntry{
				Time:      start.Format(time.RFC3339Nano),
				Method:    r.Method,
				Path:      r.URL.Path,
				Status:    ww.statusCode,
				Duration:  time.Since(start).Milliseconds(),
				IP:        ClientIP(r),
				Bytes:     ww.bytes,
				UserAgent: r.UserAgent(),
			})
		})
	}
}

type jsonlWriter struct {
	dir    string
	logger *slog.Logger
	mu     sync.Mutex
	file   *os.File
	date   string
	ch     chan accessEntry
}

func (w *jsonlWriter) write(e accessEntry) {
	if w.ch == nil {
		w.ch = make(chan accessEntry, 10000)
		go w.flusher()
	}
	select {
	case w.ch <- e:
	default:
	}
}

func (w *jsonlWriter) flusher() {
	for e := range w.ch {
		w.append(e)
	}
}

func (w *jsonlWriter) append(e accessEntry) {
	today := time.Now().Format("2006-01-02")
	w.mu.Lock()
	if w.file == nil || w.date != today {
		if w.file != nil {
			w.file.Close()
		}
		if err := os.MkdirAll(w.dir, 0o755); err != nil {
			w.mu.Unlock()
			return
		}
		f, err := os.OpenFile(filepath.Join(w.dir, "access-"+today+".jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			w.mu.Unlock()
			return
		}
		w.file = f
		w.date = today
	}
	data, _ := json.Marshal(e)
	data = append(data, '\n')
	w.file.Write(data)
	w.mu.Unlock()
}
