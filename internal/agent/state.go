package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type State struct {
	mu sync.Mutex `json:"-"`
	// ключ: "Security" / "System" и т.п.
	LastEventTime map[string]time.Time `json:"lastEventTime"`
}

func LoadState(path string) (*State, error) {
	s := &State{LastEventTime: map[string]time.Time{}}
	b, err := os.ReadFile(path)
	if err != nil {
		// нет файла — норм
		return s, nil
	}
	_ = json.Unmarshal(b, s)
	if s.LastEventTime == nil {
		s.LastEventTime = map[string]time.Time{}
	}
	return s, nil
}

func (s *State) Save(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0644)
}

func (s *State) GetLast(log string) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.LastEventTime[log]
}

func (s *State) SetLast(log string, t time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, ok := s.LastEventTime[log]; !ok || t.After(cur) {
		s.LastEventTime[log] = t
	}
}
