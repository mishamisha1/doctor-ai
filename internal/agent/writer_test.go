package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"doctor-ai/internal/model"
)

func TestReadRetainedLines_DropsOldEventsByRetention(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "edr_events.jsonl")

	oldEvt := model.Event{Timestamp: time.Now().Add(-10 * time.Hour), Type: "old"}
	newEvt := model.Event{Timestamp: time.Now().Add(-10 * time.Minute), Type: "new"}
	b1, _ := json.Marshal(oldEvt)
	b2, _ := json.Marshal(newEvt)
	if err := os.WriteFile(p, append(append(b1, '\n'), b2...), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	lines, err := readRetainedLines(p, 2*time.Hour)
	if err != nil {
		t.Fatalf("readRetainedLines: %v", err)
	}
	if len(lines) != 1 {
		t.Fatalf("expected 1 retained line, got %d", len(lines))
	}
	if string(lines[0]) == string(b1) {
		t.Fatal("old event should be removed by retention")
	}
}

func TestWriterCompact_EnforcesMaxLines(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "edr_events.jsonl")

	for i := 0; i < 5; i++ {
		evt := model.Event{Timestamp: time.Now(), Type: "x", EventID: i}
		b, _ := json.Marshal(evt)
		f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			t.Fatalf("open fixture: %v", err)
		}
		_, _ = f.Write(append(b, '\n'))
		_ = f.Close()
	}

	w, err := NewWriter(p, 24, 3)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	_ = w.f.Close()

	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	count := 0
	for _, c := range data {
		if c == '\n' {
			count++
		}
	}
	if count != 3 {
		t.Fatalf("expected 3 lines after compaction, got %d", count)
	}
}
