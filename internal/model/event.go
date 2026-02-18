package model

import "time"

type Event struct {
	Timestamp time.Time              `json:"ts"`
	Host      string                 `json:"host"`
	Source    string                 `json:"source"` // security | system | sysmon | registry
	EventID   int                    `json:"event_id"`
	Type      string                 `json:"type"`     // process_create, service_install, registry_set ...
	Severity  string                 `json:"severity"` // info | low | medium | high
	Data      map[string]interface{} `json:"data"`     // RAW payload
}
