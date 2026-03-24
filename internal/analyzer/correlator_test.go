package analyzer

import (
	"testing"
	"time"

	"doctor-ai/internal/model"
)

func TestCorrelator_AddBuildsIncidentAndResetsBuffer(t *testing.T) {
	corr := NewCorrelator(10 * time.Minute)
	base := time.Now()
	mk := func(ts time.Time, typ string, data map[string]any) model.Event {
		return model.Event{Timestamp: ts, Type: typ, Source: "sysmon", EventID: 1, Data: data}
	}
	keyData := map[string]any{"process_guid": "abc-123"}
	if inc := corr.Add(mk(base, "process_create", merge(keyData, map[string]any{"image": "powershell.exe", "command_line": "powershell -enc aaa"}))); inc != nil {
		t.Fatal("incident should not be built after first event")
	}
	if inc := corr.Add(mk(base.Add(time.Second), "file_create", merge(keyData, map[string]any{"target_file": `C:\Users\u\AppData\Local\Temp\x.exe`}))); inc != nil {
		t.Fatal("incident should not be built after second event")
	}
	inc := corr.Add(mk(base.Add(2*time.Second), "network_connect", keyData))
	if inc == nil {
		t.Fatal("expected incident on third distinct signal")
	}
	if inc.Key != "abc-123" {
		t.Fatalf("unexpected key %q", inc.Key)
	}
	if got := len(corr.buf["abc-123"]); got != 0 {
		t.Fatalf("buffer for key should be reset after incident, got %d", got)
	}
}

func TestCorrelator_TrimDropsOldEventsOutsideWindow(t *testing.T) {
	corr := NewCorrelator(time.Minute)
	base := time.Now()
	keyData := map[string]any{"process_guid": "trim-key", "image": "powershell.exe"}

	corr.Add(model.Event{Timestamp: base, Type: "process_create", Source: "sysmon", EventID: 1, Data: keyData})
	corr.Add(model.Event{Timestamp: base.Add(2 * time.Minute), Type: "process_create", Source: "sysmon", EventID: 1, Data: keyData})

	if got := len(corr.buf["trim-key"]); got != 1 {
		t.Fatalf("expected old event to be trimmed, got %d events in buffer", got)
	}
}

func merge(a, b map[string]any) map[string]any {
	out := make(map[string]any, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}
