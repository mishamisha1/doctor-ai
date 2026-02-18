package model

import "time"

type Incident struct {
	ID         string    `json:"id"`
	Key        string    `json:"key"` // process_guid / pid fallback
	Start      time.Time `json:"start"`
	End        time.Time `json:"end"`
	Score      int       `json:"score"`
	Severity   string    `json:"severity"` // low|medium|high
	Techniques []string  `json:"techniques"`
	Reasons    []string  `json:"reasons"`
	Events     []Event   `json:"events"`
}
