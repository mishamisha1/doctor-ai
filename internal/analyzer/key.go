package analyzer

import (
	"fmt"

	"doctor-ai/internal/model"
)

func CorrelationKey(evt model.Event) string {
	if evt.Data == nil {
		return ""
	}
	// сначала process_guid
	if s := strGet(evt.Data, "process_guid", "ProcessGuid", "processGuid", "ProcessGUID"); s != "" {
		return s
	}
	// fallback pid
	if p := strGet(evt.Data, "pid", "Pid", "ProcessId", "process_id"); p != "" {
		return "pid:" + p
	}
	// fallback: source+eventid
	return fmt.Sprintf("%s:%d", evt.Source, evt.EventID)
}
