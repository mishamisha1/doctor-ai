package writer

import (
	"encoding/json"
	"os"
	"sync"

	"doctor-ai/internal/model"
)

type JSONLWriter struct {
	mu   sync.Mutex
	file *os.File
}

func NewJSONLWriter(path string) (*JSONLWriter, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	return &JSONLWriter{file: f}, nil
}

func (w *JSONLWriter) Write(evt model.Event) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	b, err := json.Marshal(evt)
	if err != nil {
		return err
	}
	_, err = w.file.Write(append(b, '\n'))
	return err
}
