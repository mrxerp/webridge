package audit

import (
	"log/slog"
	"path/filepath"
	"testing"
	"time"
)

func TestStoreOffsetAndCount(t *testing.T) {
	s, err := OpenStore(filepath.Join(t.TempDir(), "audit.db"), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	batch := make([]Event, 0, 7)
	base := time.Now()
	for i := 0; i < 7; i++ {
		batch = append(batch, Event{Time: base.Add(time.Duration(i) * time.Second), Action: "download_success", User: "u1"})
	}
	s.drain(batch) // bypass async channel for deterministic test

	q := Query{Limit: 3, Action: "download_success"}
	if n := s.Count(q); n != 7 {
		t.Fatalf("Count = %d, want 7", n)
	}
	page1 := s.Query(q)
	page2 := s.Query(Query{Limit: 3, Offset: 3, Action: "download_success"})
	if len(page1) != 3 || len(page2) != 3 {
		t.Fatalf("pages len = %d/%d, want 3/3", len(page1), len(page2))
	}
	if page1[0].Time.Equal(page2[0].Time) || page1[2].Time.Equal(page2[0].Time) {
		t.Fatal("page 2 overlaps page 1")
	}
	last := s.Query(Query{Limit: 3, Offset: 6, Action: "download_success"})
	if len(last) != 1 {
		t.Fatalf("last page len = %d, want 1", len(last))
	}
}
