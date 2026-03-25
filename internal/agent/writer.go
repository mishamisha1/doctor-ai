package agent

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"doctor-ai/internal/analyzer"
	"doctor-ai/internal/model"
)

type Writer struct {
	mu    sync.Mutex
	path  string
	f     *os.File
	dedup *Deduper

	retention  time.Duration
	maxLines   int
	writeCount int
}

func NewWriter(path string, retentionHours, maxLines int) (*Writer, error) {
	w := &Writer{
		path:      path,
		dedup:     NewDeduper(60 * time.Second),
		retention: time.Duration(retentionHours) * time.Hour,
		maxLines:  maxLines,
	}
	if err := w.compact(); err != nil {
		return nil, err
	}
	if err := w.reopenAppend(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *Writer) Write(evt model.Event) {
	// 1) noise reduction
	if analyzer.IsNoise(evt) {
		return
	}

	// 2) dedup
	now := evt.Timestamp
	if now.IsZero() {
		now = time.Now()
		evt.Timestamp = now
	}
	key := DedupKey(evt)
	if w.dedup.Seen(key, now) {
		return
	}

	// 3) write jsonl
	w.mu.Lock()
	defer w.mu.Unlock()

	b, err := json.Marshal(evt)
	if err != nil {
		return
	}
	_, _ = w.f.Write(append(b, '\n'))

	w.writeCount++
	if w.writeCount%200 == 0 {
		_ = w.compactLocked()
	}
}

func (w *Writer) CompactNow() error {
	return w.compact()
}

func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	return err
}
func (w *Writer) reopenAppend() error {
	if err := os.MkdirAll(filepath.Dir(w.path), 0755); err != nil {
		return err
	}
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	w.f = f
	return nil
}

func (w *Writer) compact() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.compactLocked()
}

func (w *Writer) compactLocked() error {
	if w.retention <= 0 && w.maxLines <= 0 {
		return nil
	}
	if w.f != nil {
		_ = w.f.Sync()
		_ = w.f.Close()
		w.f = nil
	}

	lines, err := readRetainedLines(w.path, w.retention)
	if err != nil {
		_ = w.reopenAppend()
		return err
	}
	if w.maxLines > 0 && len(lines) > w.maxLines {
		lines = lines[len(lines)-w.maxLines:]
	}

	tmpPath := w.path + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(strings.Join(lines, "\n")), 0644); err != nil {
		_ = w.reopenAppend()
		return err
	}
	if len(lines) > 0 {
		if f, err := os.OpenFile(tmpPath, os.O_APPEND|os.O_WRONLY, 0644); err == nil {
			_, _ = f.Write([]byte("\n"))
			_ = f.Close()
		}
	}
	if err := os.Rename(tmpPath, w.path); err != nil {
		_ = os.Remove(tmpPath)
		_ = w.reopenAppend()
		return err
	}
	return w.reopenAppend()
}

func readRetainedLines(path string, retention time.Duration) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	cutoff := time.Time{}
	if retention > 0 {
		cutoff = time.Now().Add(-retention)
	}

	type tsOnly struct {
		Timestamp time.Time `json:"ts"`
	}

	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if !cutoff.IsZero() {
			var e tsOnly
			if err := json.Unmarshal([]byte(line), &e); err != nil {
				continue
			}
			if !e.Timestamp.IsZero() && e.Timestamp.Before(cutoff) {
				continue
			}
		}
		out = append(out, line)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
