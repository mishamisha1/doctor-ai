package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"doctor-ai/internal/agent"
	"doctor-ai/internal/model"
	"doctor-ai/internal/runner"
)

var (
	agentMu      sync.Mutex
	agentRunning bool
)

func handleHumanReport(w http.ResponseWriter, r *http.Request) {
	res, err := runner.RunAnalyze(r.Context(), runner.AnalyzeOpts{InPath: filepath.Join(logsDir, "edr_events.jsonl"), LogsDir: logsDir})
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	var sb strings.Builder
	sb.WriteString("Понятный отчёт:\n")
	if len(res.Incidents) == 0 {
		sb.WriteString("- Критичных цепочек не найдено.\n")
	} else {
		sb.WriteString(fmt.Sprintf("- Найдено инцидентов: %d\n", len(res.Incidents)))
	}
	for i, inc := range res.Incidents {
		sb.WriteString(fmt.Sprintf("\n%d) Риск: %s (score=%d), период: %s - %s\n", i+1, strings.ToUpper(inc.Severity), inc.Score, inc.Start.Format("15:04:05"), inc.End.Format("15:04:05")))
		if len(inc.Reasons) > 0 {
			sb.WriteString("   Почему: " + strings.Join(inc.Reasons, "; ") + "\n")
		}
		sb.WriteString("   Что делать: Проверьте путь процесса, изолируйте файл, перезапустите Analyze и при необходимости включите Knight Mode.\n")
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(sb.String()))
}

func handleAgent(w http.ResponseWriter, r *http.Request) {
	agentMu.Lock()
	if agentRunning {
		agentMu.Unlock()
		w.Write([]byte("[Agent] уже запущен"))
		return
	}
	agentRunning = true
	agentMu.Unlock()

	cfg, err := agent.LoadConfig(agentPath)
	if err != nil {
		agentMu.Lock()
		agentRunning = false
		agentMu.Unlock()
		http.Error(w, "config: "+err.Error(), 500)
		return
	}
	if cfg.Sysmon.Enabled && cfg.Sysmon.AutoInstall {
		if err := ensureRequiredSysmon(cfg); err != nil {
			agentMu.Lock()
			agentRunning = false
			agentMu.Unlock()
			http.Error(w, "sysmon required: "+err.Error(), 500)
			return
		}
	}
	writer, err := agent.NewWriter(cfg.Output.Path, cfg.Output.RetentionHours, cfg.Output.MaxLines)
	if err != nil {
		agentMu.Lock()
		agentRunning = false
		agentMu.Unlock()
		http.Error(w, "writer: "+err.Error(), 500)
		return
	}
	st, _ := agent.LoadState(cfg.State.Path)
	ag := agent.New(cfg, writer, st)
	go func() {
		defer func() {
			agentMu.Lock()
			agentRunning = false
			agentMu.Unlock()
		}()
		_ = ag.Run()
	}()
	w.Write([]byte("[Agent] запущен, пишет в " + cfg.Output.Path))
}

func handleLatestScan(w http.ResponseWriter, r *http.Request) {
	p, err := model.FindLatestScan(logsDir)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	scan, err := model.LoadScan(p)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	out := fmt.Sprintf("Последний скан: %s\nHost: %s | Time: %s\nProcesses: %d | Autoruns: %d | Net: %d",
		p, scan.Hostname, scan.Time, len(scan.Processes), len(scan.Autoruns), len(scan.Net))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(out))
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	host, _ := os.Hostname()
	agentMu.Lock()
	running := agentRunning
	agentMu.Unlock()
	status := map[string]interface{}{
		"host":    host,
		"agent":   running,
		"version": "1.0",
	}
	if p, err := model.FindLatestScan(logsDir); err == nil {
		status["lastScan"] = filepath.Base(p)
		if scan, err := model.LoadScan(p); err == nil {
			status["lastScanTime"] = scan.Time
			status["processes"] = len(scan.Processes)
			status["autoruns"] = len(scan.Autoruns)
		}
	}
	edrPath := filepath.Join(logsDir, "edr_events.jsonl")
	if fi, err := os.Stat(edrPath); err == nil {
		status["edrEvents"] = fi.Size()
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func handleScanHistory(w http.ResponseWriter, r *http.Request) {
	matches, err := model.FindAllScans(logsDir)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	type item struct {
		File string `json:"file"`
		Date string `json:"date"`
	}
	items := make([]item, 0, len(matches))
	for _, m := range matches {
		base := filepath.Base(m)
		// scan_20260218_123456.json -> 18 FEB
		date := base
		if len(base) >= 21 && strings.HasPrefix(base, "scan_") {
			date = base[11:13] + " " + monthName(base[9:11])
		}
		items = append(items, item{File: base, Date: date})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(items)
}

func monthName(s string) string {
	m := map[string]string{
		"01": "JAN", "02": "FEB", "03": "MAR", "04": "APR", "05": "MAY", "06": "JUN",
		"07": "JUL", "08": "AUG", "09": "SEP", "10": "OCT", "11": "NOV", "12": "DEC",
	}
	if v, ok := m[s]; ok {
		return v
	}
	return s
}

func handleEventsTail(w http.ResponseWriter, r *http.Request) {
	path := filepath.Join(logsDir, "edr_events.jsonl")
	data, err := os.ReadFile(path)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{})
		return
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 0 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{})
		return
	}
	n := 8
	if len(lines) < n {
		n = len(lines)
	}
	tail := lines[len(lines)-n:]
	// extract short preview from each line (path or type)
	previews := make([]string, 0, n)
	for _, l := range tail {
		if l == "" {
			continue
		}
		var evt struct {
			Source string                 `json:"source"`
			Type   string                 `json:"type"`
			Data   map[string]interface{} `json:"data"`
		}
		_ = json.Unmarshal([]byte(l), &evt)
		preview := evt.Source + "/" + evt.Type
		if evt.Data != nil {
			if p, ok := evt.Data["target_file"].(string); ok && p != "" {
				preview = evt.Type + ": " + p
			} else if p, ok := evt.Data["image"].(string); ok && p != "" {
				preview = evt.Type + ": " + p
			} else if p, ok := evt.Data["key"].(string); ok && p != "" {
				preview = evt.Type + ": " + p
			} else if p, ok := evt.Data["message"].(string); ok && p != "" {
				preview = p
			}
		}
		if len(preview) > 90 {
			preview = preview[:90] + "..."
		}
		previews = append(previews, preview)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(previews)
}

func handleQuickCheck(w http.ResponseWriter, r *http.Request) {
	inPath := filepath.Join(logsDir, "edr_events.jsonl")
	events, incidents, err := runner.QuickThreatCount(inPath)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"error": err.Error(), "events": 0, "incidents": 0})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"events": events, "incidents": incidents})
}
