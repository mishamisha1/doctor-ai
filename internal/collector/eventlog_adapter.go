package collector

import (
	"os"
	"strings"

	"doctor-ai/internal/model"
	"doctor-ai/internal/telemetry/eventlog"
)

func FromEventLogItem(it eventlog.Item) model.Event {
	etype := mapEventType(it.LogName, it.Id)

	return model.Event{
		Timestamp: it.TimeCreated.Time,
		Host:      hostname(),
		Source:    strings.ToLower(it.LogName),
		EventID:   it.Id,
		Type:      etype,
		Severity:  "info",
		Data: map[string]interface{}{
			"provider": it.Provider,
			"message":  it.Message,
		},
	}
}

func hostname() string {
	h, _ := os.Hostname()
	return h
}
