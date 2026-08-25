package audit

import (
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

const createSchema = `
CREATE TABLE IF NOT EXISTS audit_events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	time DATETIME NOT NULL,
	action TEXT NOT NULL,
	user TEXT DEFAULT '',
	ip TEXT DEFAULT '',
	detail TEXT DEFAULT '',
	url TEXT DEFAULT '',
	provider TEXT DEFAULT '',
	filename TEXT DEFAULT '',
	file_size INTEGER DEFAULT 0,
	mime_type TEXT DEFAULT '',
	resolved_url TEXT DEFAULT '',
	bytes_transferred INTEGER DEFAULT 0,
	duration_ms INTEGER DEFAULT 0,
	sha256 TEXT DEFAULT '',
	anomaly_flags TEXT DEFAULT '',
	client_ua TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_ae_time ON audit_events(time);
CREATE INDEX IF NOT EXISTS idx_ae_action ON audit_events(action);
CREATE INDEX IF NOT EXISTS idx_ae_user ON audit_events(user);
`

// Store is a SQLite-backed persistent audit store.
type Store struct {
	db      *sql.DB
	ch      chan Event
	logger  *slog.Logger
	done    chan struct{}
}

// OpenStore opens (or creates) a SQLite database and starts the async writer.
func OpenStore(dbPath string, logger *slog.Logger) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return nil, fmt.Errorf("audit store: mkdir: %w", err)
	}
	db, err := sql.Open("sqlite", dbPath+"?_journal_mode=WAL&_busy_timeout=5000&_synchronous=NORMAL")
	if err != nil {
		return nil, fmt.Errorf("audit store: open: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	if _, err := db.Exec(createSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("audit store: schema: %w", err)
	}

	s := &Store{
		db:     db,
		ch:     make(chan Event, 10000),
		logger: logger,
		done:   make(chan struct{}),
	}
	go s.flusher()
	return s, nil
}

func (s *Store) enqueue(e Event) {
	select {
	case s.ch <- e:
	default:
		s.logger.Warn("audit buffer full, event dropped", "action", e.Action)
	}
}

func (s *Store) flusher() {
	defer close(s.done)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	batch := make([]Event, 0, 500)
	for {
		select {
		case e, ok := <-s.ch:
			if !ok {
				return
			}
			batch = append(batch, e)
			if len(batch) >= 500 {
				s.drain(batch)
				batch = batch[:0]
			}
		case <-ticker.C:
			if len(batch) > 0 {
				s.drain(batch)
				batch = batch[:0]
			}
		}
	}
}

func (s *Store) drain(batch []Event) {
	if len(batch) == 0 {
		return
	}
	tx, err := s.db.Begin()
	if err != nil {
		s.logger.Error("audit store: begin tx", "err", err, "dropped", len(batch))
		return
	}
	stmt, err := tx.Prepare(`INSERT INTO audit_events
		(time, action, user, ip, detail, url, provider, filename, file_size, mime_type,
		 resolved_url, bytes_transferred, duration_ms, sha256, anomaly_flags, client_ua)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		tx.Rollback()
		s.logger.Error("audit store: prepare", "err", err, "dropped", len(batch))
		return
	}
	defer stmt.Close()
	for _, e := range batch {
		stmt.Exec(e.Time.Format(time.RFC3339Nano), e.Action, e.User, e.IP, e.Detail,
			e.URL, e.Provider, e.Filename, e.FileSize, "",
			e.ResolvedURL, e.BytesTransferred, e.DurationMS, e.SHA256,
			"", e.ClientUA)
	}
	if err := tx.Commit(); err != nil {
		s.logger.Error("audit store: commit", "err", err, "dropped", len(batch))
	}
}

// Close waits for buffered events to flush and closes the database.
func (s *Store) Close() {
	close(s.ch)
	<-s.done
	s.db.Close()
}

// Purge deletes events older than retentionDays. Call on startup and daily.
func (s *Store) Purge(retentionDays int) {
	if retentionDays <= 0 {
		return
	}
	cutoff := time.Now().AddDate(0, 0, -retentionDays).Format(time.RFC3339)
	res, err := s.db.Exec("DELETE FROM audit_events WHERE time < ?", cutoff)
	if err != nil {
		s.logger.Error("audit store: purge", "err", err)
		return
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		s.logger.Info("audit store: purged old events", "count", n, "cutoff", cutoff)
	}
	s.db.Exec("VACUUM")
}

// filterClause builds the WHERE fragment and args shared by Query and Count.
func filterClause(q Query) (string, []any) {
	where := "1=1"
	args := []any{}
	if q.Action != "" {
		where += " AND action = ?"
		args = append(args, q.Action)
	}
	if q.User != "" {
		where += " AND user LIKE ?"
		args = append(args, "%"+q.User+"%")
	}
	if q.FromMs > 0 {
		where += " AND time >= ?"
		args = append(args, time.UnixMilli(q.FromMs).Format(time.RFC3339))
	}
	if q.ToMs > 0 {
		where += " AND time <= ?"
		args = append(args, time.UnixMilli(q.ToMs).Format(time.RFC3339))
	}
	return where, args
}

// Query retrieves events from SQLite, newest first.
func (s *Store) Query(q Query) []Event {
	limit := q.Limit
	if limit <= 0 {
		limit = 1000
	}
	offset := q.Offset
	if offset < 0 {
		offset = 0
	}

	where, args := filterClause(q)

	query := fmt.Sprintf(`SELECT time, action, user, ip, detail, url, provider, filename,
		file_size, mime_type, resolved_url, bytes_transferred, duration_ms, sha256, anomaly_flags, client_ua
		FROM audit_events WHERE %s ORDER BY time DESC LIMIT ? OFFSET ?`, where)
	args = append(args, limit, offset)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		s.logger.Error("audit store: query", "err", err)
		return nil
	}
	defer rows.Close()

	var out []Event
	for rows.Next() {
		var e Event
		var t, mimeType, flags string
		rows.Scan(&t, &e.Action, &e.User, &e.IP, &e.Detail, &e.URL,
			&e.Provider, &e.Filename, &e.FileSize, &mimeType,
			&e.ResolvedURL, &e.BytesTransferred, &e.DurationMS, &e.SHA256,
			&flags, &e.ClientUA)
		e.Time, _ = time.Parse(time.RFC3339Nano, t)
		out = append(out, e)
	}
	return out
}

// Count returns the number of events matching the query's filters.
func (s *Store) Count(q Query) int64 {
	where, args := filterClause(q)
	var n int64
	s.db.QueryRow("SELECT COUNT(*) FROM audit_events WHERE "+where, args...).Scan(&n)
	return n
}

// TotalBytes returns the sum of bytes_transferred for events matching the action.
func (s *Store) TotalBytes(action string) int64 {
	var n int64
	if action != "" {
		s.db.QueryRow("SELECT COALESCE(SUM(bytes_transferred), 0) FROM audit_events WHERE action = ?", action).Scan(&n)
	} else {
		s.db.QueryRow("SELECT COALESCE(SUM(bytes_transferred), 0) FROM audit_events").Scan(&n)
	}
	return n
}
