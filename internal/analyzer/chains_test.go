package analyzer

import (
	"testing"
	"time"

	"doctor-ai/internal/model"
)

func TestMatchChain_TriggersOnThreeSignals(t *testing.T) {
	now := time.Now()
	events := []model.Event{
		{Timestamp: now, Type: "process_create", Data: map[string]any{"image": `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`, "command_line": "powershell -enc abc"}},
		{Timestamp: now.Add(time.Second), Type: "file_create", Data: map[string]any{"target_file": `C:\Users\u\AppData\Local\Temp\drop.exe`}},
		{Timestamp: now.Add(2 * time.Second), Type: "autorun_change", Data: map[string]any{"key": `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`}},
	}

	ok, tech, reasons := matchChain(events)
	if !ok {
		t.Fatal("expected chain to match")
	}
	if len(tech) == 0 || len(reasons) < 3 {
		t.Fatalf("expected techniques and reasons, got tech=%v reasons=%v", tech, reasons)
	}
}

func TestMatchChain_DoesNotTriggerOnTwoSignals(t *testing.T) {
	events := []model.Event{
		{Type: "process_create", Data: map[string]any{"image": "powershell.exe"}},
		{Type: "network_connect", Data: map[string]any{"dst_ip": "1.1.1.1"}},
	}

	ok, _, _ := matchChain(events)
	if ok {
		t.Fatal("expected chain not to match on only two signals")
	}
}
