package agent

import (
	"encoding/json"
	"os"
	"sync"
	"time"

	"doctor-ai/internal/analyzer"
	"doctor-ai/internal/model"
)

type Writer struct {
	mu    sync.Mutex
	f     *os.File
	dedup *Deduper
}

func NewWriter(path string) (*Writer, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	return &Writer{
		f:     f,
		dedup: NewDeduper(60 * time.Second),
	}, nil
}

func (w *Writer) Write(evt model.Event) {
	// 1) noise reduction
	if analyzer.IsNoise(evt) {
		// вариант A: вообще не писать шум
		return

		// вариант B (если хочешь хранить шум, но помечать):
		// if evt.Data == nil { evt.Data = map[string]interface{}{} }
		// evt.Data["noise"] = true
		// if evt.Severity == "" || evt.Severity == "info" { evt.Severity = "info" }
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
}
