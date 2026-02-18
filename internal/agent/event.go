package agent

import "time"

type Event struct {
	Timestamp time.Time      `json:"timestamp"`
	Level     string         `json:"level"`  // info | alert | error
	Source    string         `json:"source"` // agent | eventlog | detector
	Type      string         `json:"type"`   // heartbeat | process | alert
	Message   string         `json:"message"`
	Data      map[string]any `json:"data,omitempty"`
}
