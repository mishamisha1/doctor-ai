package simulate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"doctor-ai/internal/model"
)

func GenerateEvents(scenario string, count int) []model.Event {
	if count <= 0 {
		count = 20
	}
	now := time.Now().Add(-2 * time.Minute)
	out := make([]model.Event, 0, count)
	addMal := func(i int) {
		key := map[string]interface{}{"process_guid": fmt.Sprintf("sim-mal-%d", i), "pid": fmt.Sprintf("%d", 7000+i)}
		out = append(out,
			model.Event{Timestamp: now.Add(time.Duration(i) * time.Second), Host: "SIM", Source: "sysmon", EventID: 1, Type: "process_create", Severity: "high", Data: mergeData(key, map[string]interface{}{"image": `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "command_line": "powershell -enc AAAA"})},
			model.Event{Timestamp: now.Add(time.Duration(i)*time.Second + time.Second), Host: "SIM", Source: "sysmon", EventID: 11, Type: "file_create", Severity: "medium", Data: mergeData(key, map[string]interface{}{"target_file": `C:\Users\User\AppData\Local\Temp\dropper.exe`})},
			model.Event{Timestamp: now.Add(time.Duration(i)*time.Second + 2*time.Second), Host: "SIM", Source: "registry", EventID: 13, Type: "autorun_change", Severity: "high", Data: mergeData(key, map[string]interface{}{"key": `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, "name": "Updater"})},
			model.Event{Timestamp: now.Add(time.Duration(i)*time.Second + 3*time.Second), Host: "SIM", Source: "sysmon", EventID: 3, Type: "network_connect", Severity: "medium", Data: mergeData(key, map[string]interface{}{"dst_ip": "203.0.113.10"})},
		)
	}
	addBen := func(i int) {
		key := map[string]interface{}{"process_guid": fmt.Sprintf("sim-ben-%d", i), "pid": fmt.Sprintf("%d", 4000+i)}
		out = append(out,
			model.Event{Timestamp: now.Add(time.Duration(i) * time.Second), Host: "SIM", Source: "security", EventID: 4688, Type: "process_create", Severity: "info", Data: mergeData(key, map[string]interface{}{"image": `C:\Windows\System32\notepad.exe`, "command_line": "notepad.exe"})},
			model.Event{Timestamp: now.Add(time.Duration(i)*time.Second + time.Second), Host: "SIM", Source: "sysmon", EventID: 3, Type: "network_connect", Severity: "low", Data: mergeData(key, map[string]interface{}{"dst_ip": "1.1.1.1"})},
		)
	}
	for i := 0; i < count; i++ {
		switch strings.ToLower(strings.TrimSpace(scenario)) {
		case "malicious":
			addMal(i)
		case "benign":
			addBen(i)
		default:
			if i%2 == 0 {
				addMal(i)
			} else {
				addBen(i)
			}
		}
	}
	return out
}

func WriteJSONL(path string, events []model.Event) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, e := range events {
		b, _ := json.Marshal(e)
		if _, err := f.Write(append(b, '\n')); err != nil {
			return err
		}
	}
	return nil
}

func mergeData(a, b map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}
