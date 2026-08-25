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
	UserAgent string `json:"user_agent"`
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func AccessLog(dir string, logger *slog.Logger) func(http.Handler) http.Handler {
	var w *jsonlWriter
	if dir != "" {
		w = &jsonlWriter{dir: dir, logger: logger}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := &responseWriter{ResponseWriter: rw, statusCode: http.StatusOK}
			next.ServeHTTP(ww, r)
			duration := time.Since(start)

			logger.Info("request",
				"method", r.Method,
				"path", r.URL.Path,
				"query", r.URL.RawQuery,
				"status", ww.statusCode,
				"duration_ms", duration.Milliseconds(),
				"ip", ClientIP(r),
				"user_agent", r.UserAgent(),
			)

			if w != nil {
				w.write(accessEntry{
					Time:      start.Format(time.RFC3339Nano),
					Method:    r.Method,
					Path:      r.URL.Path,
					Status:    ww.statusCode,
					Duration:  duration.Milliseconds(),
					IP:        ClientIP(r),
					UserAgent: r.UserAgent(),
				})
			}
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
		w.writeLine(e)
	}
}

func (w *jsonlWriter) writeLine(e accessEntry) {
	today := time.Now().Format("2006-01-02")
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.date != today || w.file == nil {
		if w.file != nil {
			w.file.Close()
		}
		os.MkdirAll(w.dir, 0o755)
		path := filepath.Join(w.dir, "access-"+today+".jsonl")
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			w.logger.Warn("failed to open access log", "path", path, "error", err)
			return
		}
		w.file = f
		w.date = today
	}

	data, err := json.Marshal(e)
	if err != nil {
		return
	}
	data = append(data, '\n')
	w.file.Write(data)
}
