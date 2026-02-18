package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"doctor-ai/internal/agent"
	"doctor-ai/internal/collector"
	"doctor-ai/internal/hashlist"
	"doctor-ai/internal/model"
	"doctor-ai/internal/runner"
	"doctor-ai/internal/virustotal"
)

//go:embed embedded/configs
var configsFS embed.FS

var (
	baseDir    string
	ps1Path    string
	policyPath string
	logsDir    string
)

func init() {
	self, _ := os.Executable()
	baseDir = filepath.Dir(self)
	_ = os.Chdir(baseDir)
	ps1Path = filepath.Join(baseDir, "configs", "doctor.ps1")
	policyPath = filepath.Join(baseDir, "configs", "policy.json")
	logsDir = filepath.Join(baseDir, "logs")
	
	// Создаём директории и файлы из встроенных, если их нет
	os.MkdirAll(filepath.Join(baseDir, "configs"), 0755)
	os.MkdirAll(logsDir, 0755)
	
	// Если doctor.ps1 нет — создаём из встроенного
	if _, err := os.Stat(ps1Path); os.IsNotExist(err) {
		data, err := fs.ReadFile(configsFS, "embedded/configs/doctor.ps1")
		if err == nil {
			if err := os.WriteFile(ps1Path, data, 0644); err != nil {
				log.Printf("WARN: failed to create doctor.ps1: %v", err)
			}
		} else {
			log.Printf("WARN: failed to read embedded doctor.ps1: %v", err)
		}
	}
	
	// Если policy.json нет — создаём из встроенного
	if _, err := os.Stat(policyPath); os.IsNotExist(err) {
		data, err := fs.ReadFile(configsFS, "embedded/configs/policy.json")
		if err == nil {
			if err := os.WriteFile(policyPath, data, 0644); err != nil {
				log.Printf("WARN: failed to create policy.json: %v", err)
			}
		} else {
			log.Printf("WARN: failed to read embedded policy.json: %v", err)
		}
	}
}

func main() {
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/api/run", handleRun)
	http.HandleFunc("/api/analyze", handleAnalyze)
	http.HandleFunc("/api/agent", handleAgent)
	http.HandleFunc("/api/ai-key", handleAIKey)
	http.HandleFunc("/api/latest-scan", handleLatestScan)
	http.HandleFunc("/api/status", handleStatus)
	http.HandleFunc("/api/scan-history", handleScanHistory)
	http.HandleFunc("/api/quick-check", handleQuickCheck)
	http.HandleFunc("/api/events-tail", handleEventsTail)
	http.HandleFunc("/api/flagged-paths", handleFlaggedPaths)
	http.HandleFunc("/api/upload-analyze", handleUploadAnalyze)
	http.HandleFunc("/api/quarantine-hashes", handleQuarantineHashes)
	http.HandleFunc("/api/vt-key", handleVTKey)
	http.HandleFunc("/api/hashlist", handleHashlist)
	http.HandleFunc("/api/vt-file-list", handleVTFileList)
	http.HandleFunc("/api/check-file-vt", handleCheckFileVT)

	addr := "127.0.0.1:19527"
	url := "http://" + addr
	fmt.Println("Doctor-AI GUI: " + url)
	openBrowser(url)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(htmlPage))
}

func runPS1(cmd string, auto bool) (string, error) {
	return collector.RunDoctorPS1WithOutput(collector.PS1Args{
		PS1Path: ps1Path, Cmd: cmd, PolicyPath: policyPath, Auto: auto, WorkingDir: baseDir,
	})
}

func handleRun(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	cmd := r.FormValue("cmd")
	auto := r.FormValue("auto") == "1"
	if cmd == "" {
		http.Error(w, "missing cmd", 400)
		return
	}
	desc := runner.CommandDescriptions[cmd]
	out, err := runPS1(cmd, auto)
	result := desc + "\n\n--- вывод ---\n" + out
	if err != nil {
		result += "\n[ОШИБКА] " + err.Error()
	} else {
		result += "\n[OK]"
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(result))
}

func handleAnalyze(w http.ResponseWriter, r *http.Request) {
	res, err := runner.RunAnalyze(r.Context(), runner.AnalyzeOpts{
		InPath:   filepath.Join(logsDir, "edr_events.jsonl"),
		LogsDir:  logsDir,
		EnableAI: true,
		AIMax:    5,
		AIModel:  "gpt-4o-mini",
	})
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	out := res.Log.String()
	for i, rep := range res.AIReports {
		out += "\n\n========== AI Report " + fmt.Sprintf("%d", i+1) + " ==========\n" + rep
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(out))
}

var agentRunning bool

func handleAgent(w http.ResponseWriter, r *http.Request) {
	if agentRunning {
		w.Write([]byte("[Agent] уже запущен"))
		return
	}
	cfg, err := agent.LoadConfig(filepath.Join(baseDir, "configs", "agent.json"))
	if err != nil {
		http.Error(w, "config: "+err.Error(), 500)
		return
	}
	writer, err := agent.NewWriter(cfg.Output.Path)
	if err != nil {
		http.Error(w, "writer: "+err.Error(), 500)
		return
	}
	st, _ := agent.LoadState(cfg.State.Path)
	ag := agent.New(cfg, writer, st)
	agentRunning = true
	go func() {
		_ = ag.Run()
		agentRunning = false
	}()
	w.Write([]byte("[Agent] запущен, пишет в " + cfg.Output.Path))
}

func handleAIKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST only", 405)
		return
	}
	key := r.FormValue("key")
	if key == "" {
		http.Error(w, "empty key", 400)
		return
	}
	keyPath := filepath.Join(logsDir, ".openai_key")
	if err := os.WriteFile(keyPath, []byte(key), 0600); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Write([]byte("OK"))
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
	status := map[string]interface{}{
		"host":    host,
		"agent":   agentRunning,
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
			Source string `json:"source"`
			Type   string `json:"type"`
			Data   map[string]interface{} `json:"data"`
		}
		_ = json.Unmarshal([]byte(l), &evt)
		preview := evt.Source + "/" + evt.Type
		if evt.Data != nil {
			if p, ok := evt.Data["message"].(string); ok && len(p) > 0 {
				if len(p) > 60 {
					p = p[:60] + "..."
				}
				preview = p
			}
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

func handleFlaggedPaths(w http.ResponseWriter, r *http.Request) {
	res, err := runner.RunAnalyze(r.Context(), runner.AnalyzeOpts{
		InPath:   filepath.Join(logsDir, "edr_events.jsonl"),
		LogsDir:  logsDir,
		EnableAI: false,
	})
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{})
		return
	}
	type item struct {
		Path     string `json:"path"`
		Severity string `json:"severity"`
		Reasons  string `json:"reasons"`
	}
	items := make([]item, 0)
	for _, inc := range res.Incidents {
		for _, e := range inc.Events {
			path := ""
			if e.Data != nil {
				for _, k := range []string{"image", "target_file", "TargetFilename", "path", "Image"} {
					if v, ok := e.Data[k]; ok {
						if s, ok := v.(string); ok && s != "" {
							path = s
							break
						}
					}
				}
			}
			if path != "" {
				items = append(items, item{Path: path, Severity: inc.Severity, Reasons: strings.Join(inc.Reasons, "; ")})
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(items)
}

func handleUploadAnalyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST only", 405)
		return
	}
	f, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "no file", 400)
		return
	}
	defer f.Close()
	paths := r.FormValue("paths")
	if paths != "" {
		pathList := strings.Split(paths, "\n")
		result := "Пути для проверки:\n"
		for _, p := range pathList {
			p = strings.TrimSpace(p)
			if p != "" {
				result += "- " + p + "\n"
			}
		}
		result += "\nЗапустите Analyze для корреляции с EDR-событиями."
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(result))
		return
	}
	_ = f
	w.Write([]byte("Файл получен. Загрузите путь или используйте Analyze для полной проверки."))
}

func handleQuarantineHashes(w http.ResponseWriter, r *http.Request) {
	qDir := filepath.Join(baseDir, "quarantine")
	entries, err := os.ReadDir(qDir)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]interface{}{})
		return
	}
	type item struct {
		Name string `json:"name"`
		Path string `json:"path"`
	}
	items := make([]item, 0)
	for _, e := range entries {
		if !e.IsDir() {
			items = append(items, item{Name: e.Name(), Path: filepath.Join(qDir, e.Name())})
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(items)
}

func handleHashlist(w http.ResponseWriter, r *http.Request) {
	hl, err := hashlist.New(
		filepath.Join(logsDir, "whitelist_hashes.json"),
		filepath.Join(logsDir, "blacklist_hashes.json"),
	)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"whitelist": []string{}, "blacklist": []string{}})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"whitelist": hl.Whitelist(),
		"blacklist": hl.Blacklist(),
	})
}

func handleVTFileList(w http.ResponseWriter, r *http.Request) {
	scans, _ := model.FindAllScans(logsDir)
	edrGlob, _ := filepath.Glob(filepath.Join(logsDir, "edr_*.jsonl"))
	type fileItem struct {
		Name string `json:"name"`
		Path string `json:"path"`
	}
	scanItems := make([]fileItem, 0, len(scans))
	for _, p := range scans {
		scanItems = append(scanItems, fileItem{Name: filepath.Base(p), Path: p})
	}
	edrItems := make([]fileItem, 0, len(edrGlob))
	for _, p := range edrGlob {
		edrItems = append(edrItems, fileItem{Name: filepath.Base(p), Path: p})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"scans": scanItems,
		"edr":   edrItems,
	})
}

func handleCheckFileVT(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST only", 405)
		return
	}
	filePath := r.FormValue("path")
	if filePath == "" {
		http.Error(w, "missing path", 400)
		return
	}
	// path must be under logsDir or baseDir
	if !strings.HasPrefix(filepath.Clean(filePath), filepath.Clean(logsDir)) &&
		!strings.HasPrefix(filepath.Clean(filePath), filepath.Clean(baseDir)) {
		http.Error(w, "forbidden path", 403)
		return
	}
	hashes, err := runner.ExtractHashesFromFile(filePath)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	hl, err := hashlist.New(
		filepath.Join(logsDir, "whitelist_hashes.json"),
		filepath.Join(logsDir, "blacklist_hashes.json"),
	)
	if err != nil {
		http.Error(w, "hashlist: "+err.Error(), 500)
		return
	}
	vtKey, _ := os.ReadFile(filepath.Join(logsDir, ".vt_key"))
	vt := virustotal.NewClient(strings.TrimSpace(string(vtKey)))
	if vt.APIKey == "" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("Сначала сохраните VirusTotal API ключ в настройках."))
		return
	}

	var logOut strings.Builder
	logOut.WriteString(fmt.Sprintf("Файл: %s\n", filepath.Base(filePath)))
	logOut.WriteString(fmt.Sprintf("Найдено хэшей: %d\n\n", len(hashes)))
	checked, white, black := 0, 0, 0
	for _, h := range hashes {
		if hl.IsWhitelisted(h) {
			logOut.WriteString(fmt.Sprintf("%s... whitelist (пропуск)\n", h[:min(16, len(h))]))
			white++
			continue
		}
		if hl.IsBlacklisted(h) {
			logOut.WriteString(fmt.Sprintf("%s... blacklist (пропуск)\n", h[:min(16, len(h))]))
			black++
			continue
		}
		pos, tot, err := vt.CheckHash(r.Context(), h)
		checked++
		if err != nil {
			logOut.WriteString(fmt.Sprintf("%s... VT ошибка: %v\n", h[:min(16, len(h))], err))
			continue
		}
		if tot == 0 {
			logOut.WriteString(fmt.Sprintf("%s... VT: не найден\n", h[:min(16, len(h))]))
			continue
		}
		if pos > 0 {
			_ = hl.AddToBlacklist(h)
			logOut.WriteString(fmt.Sprintf("%s... VT %d/%d -> blacklist\n", h[:min(16, len(h))], pos, tot))
			black++
		} else {
			_ = hl.AddToWhitelist(h)
			logOut.WriteString(fmt.Sprintf("%s... VT 0/%d -> whitelist\n", h[:min(16, len(h))], tot))
			white++
		}
	}
	logOut.WriteString(fmt.Sprintf("\nИтого: проверено %d, добавлено в whitelist: %d, в blacklist: %d", checked, white, black))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(logOut.String()))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func handleVTKey(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		key := r.FormValue("key")
		keyPath := filepath.Join(logsDir, ".vt_key")
		if err := os.WriteFile(keyPath, []byte(key), 0600); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Write([]byte("OK"))
		return
	}
	keyPath := filepath.Join(logsDir, ".vt_key")
	if _, err := os.Stat(keyPath); err == nil {
		w.Write([]byte("1"))
	} else {
		w.Write([]byte("0"))
	}
}

const htmlPage = `<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Doctor-AI — Anti-Malware Engine</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
<style>
:root {
  --bg-dark: #0d1117;
  --bg-card: #161b22;
  --bg-sidebar: #0d1117;
  --border: #30363d;
  --accent: #58a6ff;
  --accent-dim: #388bfd;
  --success: #3fb950;
  --warning: #d29922;
  --danger: #f85149;
  --text: #e6edf3;
  --text-muted: #8b949e;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Inter', -apple-system, sans-serif; background: var(--bg-dark); color: var(--text); min-height: 100vh; overflow-x: hidden; }
.layout { display: flex; flex-direction: column; min-height: 100vh; }

/* Header */
.header {
  background: linear-gradient(135deg, #0d1117 0%, #161b22 50%, #0d1117 100%);
  border-bottom: 1px solid var(--border);
  padding: 12px 24px;
  display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px;
}
.header h1 { font-size: 1.4rem; font-weight: 700; background: linear-gradient(90deg, #58a6ff, #a371f7); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
.badges { display: flex; gap: 8px; flex-wrap: wrap; }
.badge { font-size: 11px; padding: 4px 10px; border-radius: 20px; font-weight: 600; }
.badge-go { background: #238636; color: #fff; }
.badge-ver { background: #1f6feb; color: #fff; }
.badge-safe { background: var(--success); color: #000; display: flex; align-items: center; gap: 4px; }
.badge-safe::before { content: '✓'; font-weight: bold; }

/* Main content */
.main { display: flex; flex: 1; min-height: 0; }
.sidebar {
  width: 220px; background: var(--bg-sidebar); border-right: 1px solid var(--border);
  padding: 20px 0; display: flex; flex-direction: column; gap: 8px;
}
.sidebar .logo { padding: 0 20px 16px; font-size: 24px; }
.sidebar .greeting { padding: 0 20px 12px; font-size: 13px; color: var(--text-muted); }
.nav-item {
  padding: 10px 20px; cursor: pointer; border-left: 3px solid transparent; color: var(--text-muted);
  font-size: 14px; display: flex; align-items: center; gap: 10px; transition: all 0.2s;
}
.nav-item:hover { color: var(--accent); background: rgba(88,166,255,0.08); }
.nav-item.active { color: var(--accent); border-left-color: var(--accent); background: rgba(88,166,255,0.1); }
.nav-item .icon { font-size: 16px; opacity: 0.8; }

.content { flex: 1; padding: 24px; overflow: auto; display: flex; gap: 24px; }
.center { flex: 1; display: flex; flex-direction: column; gap: 20px; min-width: 0; }
.right { width: 260px; flex-shrink: 0; }

/* Progress circle */
.progress-box {
  background: var(--bg-card); border: 1px solid var(--border); border-radius: 16px;
  padding: 32px; display: flex; flex-direction: column; align-items: center; gap: 16px;
}
.progress-ring {
  width: 140px; height: 140px; border-radius: 50%;
  background: conic-gradient(var(--accent) calc(var(--p)*1%), var(--border) 0);
  display: flex; align-items: center; justify-content: center;
}
.progress-ring-inner {
  width: 110px; height: 110px; border-radius: 50%; background: var(--bg-card);
  display: flex; align-items: center; justify-content: center; font-size: 28px; font-weight: 700;
}
.controls { display: flex; gap: 12px; }
.ctrl-btn { width: 40px; height: 40px; border-radius: 50%; border: 1px solid var(--border); background: var(--bg-dark); color: var(--text); cursor: pointer; font-size: 16px; }
.ctrl-btn:hover { background: var(--border); }
.threats { display: flex; align-items: center; gap: 8px; color: var(--warning); font-weight: 600; }
.threats .warn-icon { font-size: 20px; }

/* Log / Output */
.log-box {
  background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px;
  padding: 16px; font-family: 'JetBrains Mono', monospace; font-size: 12px;
  white-space: pre-wrap; word-break: break-all; overflow: auto; max-height: 280px; min-height: 120px;
}
.log-box::-webkit-scrollbar { width: 8px; }
.log-box::-webkit-scrollbar-track { background: var(--bg-dark); border-radius: 4px; }
.log-box::-webkit-scrollbar-thumb { background: var(--border); border-radius: 4px; }

.activity-box { background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 16px; }
.activity-box h4 { margin-bottom: 10px; font-size: 12px; color: var(--text-muted); }
.activity-list { font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--text-muted); max-height: 80px; overflow: auto; }
.activity-list div { padding: 4px 0; border-bottom: 1px solid var(--border); }
.activity-list div:last-child { border-bottom: none; }
.tip-box { background: rgba(88,166,255,0.1); border: 1px solid rgba(88,166,255,0.3); border-radius: 10px; padding: 12px; font-size: 13px; }

/* Scan history */
.history-box { background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 16px; }
.history-box h4 { margin-bottom: 12px; font-size: 12px; color: var(--text-muted); text-transform: uppercase; }
.history-dates { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
.hist-date { padding: 8px 14px; border-radius: 8px; background: var(--bg-dark); color: var(--text-muted); font-size: 12px; cursor: pointer; }
.hist-date:hover { color: var(--accent); }
.hist-date.active { background: rgba(88,166,255,0.2); color: var(--accent); }
.hist-nav { color: var(--text-muted); cursor: pointer; padding: 4px; }
.hist-nav:hover { color: var(--accent); }

/* Right panel - Protection */
.protection-box { background: var(--bg-card); border: 1px solid var(--border); border-radius: 16px; padding: 20px; }
.protection-box h4 { margin-bottom: 16px; font-size: 13px; display: flex; align-items: center; gap: 8px; }
.protection-item { margin-bottom: 16px; }
.protection-item:last-child { margin-bottom: 0; }
.protection-item label { font-size: 12px; color: var(--text-muted); display: block; margin-bottom: 6px; }
.slider-wrap { display: flex; align-items: center; gap: 10px; }
.slider { flex: 1; height: 6px; -webkit-appearance: none; background: var(--border); border-radius: 3px; }
.slider::-webkit-slider-thumb { -webkit-appearance: none; width: 16px; height: 16px; border-radius: 50%; background: var(--accent); cursor: pointer; }

/* Action buttons grid */
.actions { display: grid; grid-template-columns: repeat(auto-fill, minmax(100px, 1fr)); gap: 8px; }
.btn { padding: 10px 14px; border-radius: 10px; border: 1px solid var(--border); background: var(--bg-card); color: var(--text); cursor: pointer; font-size: 13px; font-weight: 500; transition: all 0.2s; }
.btn:hover { background: var(--accent); color: #000; border-color: var(--accent); }
.btn-primary { background: var(--accent); color: #000; border-color: var(--accent); }
.btn-primary:hover { background: var(--accent-dim); }
.btn-danger:hover { background: var(--danger); border-color: var(--danger); color: #fff; }

/* Settings / API Key */
.settings-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 16px; margin-top: 16px; }
.settings-card input { width: 100%; padding: 10px; background: var(--bg-dark); border: 1px solid var(--border); border-radius: 8px; color: var(--text); margin-top: 8px; }
.section-panel { display: none; }
.section-panel.active { display: flex; flex-direction: column; gap: 20px; }
.modal-overlay { display: none; position: fixed; top:0; left:0; right:0; bottom:0; background: rgba(0,0,0,0.8); z-index: 9999; align-items: center; justify-content: center; }
.modal-overlay.visible { display: flex; }
.modal-box { background: var(--bg-card); border: 1px solid var(--accent); border-radius: 16px; padding: 32px; text-align: center; max-width: 400px; }
.modal-box h3 { margin-bottom: 12px; color: var(--accent); }
.modal-box p { color: var(--text-muted); font-size: 14px; }
.spinner { width: 40px; height: 40px; border: 3px solid var(--border); border-top-color: var(--accent); border-radius: 50%; animation: spin 0.8s linear infinite; margin: 0 auto 16px; }
@keyframes spin { to { transform: rotate(360deg); } }
.btn.working { background: var(--accent); color: #000; }
</style>
</head>
<body>
<div class="layout">
<header class="header">
  <h1>Doctor-AI — Anti-Malware Engine</h1>
  <div class="badges">
    <span class="badge badge-go">Go 1.25</span>
    <span class="badge badge-ver">v1.0</span>
    <span class="badge badge-safe" id="statusBadge">Загрузка...</span>
  </div>
</header>

<div class="main">
<aside class="sidebar">
  <div class="logo">🩺</div>
  <div class="greeting" id="greeting">Привет!</div>
  <div class="nav-item active" data-section="scan"><span class="icon">🔍</span> Scan</div>
  <div class="nav-item" data-section="protect"><span class="icon">🛡</span> Protect</div>
  <div class="nav-item" data-section="quarantine"><span class="icon">🔒</span> Quarantine</div>
  <div class="nav-item" data-section="update"><span class="icon">🔄</span> Update</div>
  <div class="nav-item" data-section="settings"><span class="icon">⚙</span> Settings</div>
</aside>

<div class="content">
<div class="center" style="flex:1;flex-direction:column">

<!-- SCAN -->
<div id="panel-scan" class="section-panel active">
  <div class="progress-box">
    <div class="progress-ring" id="progressRing" style="--p: 0">
      <div class="progress-ring-inner" id="progressPercent">0%</div>
    </div>
    <div class="threats" id="threatsBox">
      <span class="warn-icon">⚠</span>
      <span id="threatsCount">— угроз</span>
    </div>
  </div>
  <div class="actions">
    <button class="btn" data-cmd="scan" onclick="run('scan',this)">Scan</button>
    <button class="btn" data-cmd="plan" onclick="run('plan',this)">Plan</button>
    <button class="btn" data-cmd="fix" onclick="run('fix',this)">Fix</button>
    <button class="btn" data-cmd="fix-auto" onclick="run('fix',this,1)">Fix -Auto</button>
    <button class="btn btn-danger" data-cmd="rollback" onclick="run('rollback',this)">Rollback</button>
    <button class="btn" data-cmd="avscan" onclick="run('avscan',this)">AV Scan</button>
    <button class="btn" data-cmd="analyze" onclick="analyze(this)">Analyze AI</button>
    <button class="btn" data-cmd="agent" onclick="agentRun(this)">Agent</button>
    <button class="btn" data-cmd="latestScan" onclick="latestScan(this)">Latest Scan</button>
  </div>
  <div class="log-box" id="out">Scan: телеметрия. Plan: план. Fix: применить. Analyze: EDR+AI.</div>
  <div class="activity-box">
    <h4>📡 Активность</h4>
    <div id="activityList" class="activity-list"></div>
    <button class="btn" style="margin-top:8px" onclick="refreshActivity()">Обновить</button>
  </div>
  <div class="history-box">
    <h4>📅 История сканов</h4>
    <div class="history-dates" id="historyDates"></div>
  </div>
</div>

<!-- PROTECT -->
<div id="panel-protect" class="section-panel">
  <div class="settings-card">
    <h4>Загрузить подозрительные файлы или пути</h4>
    <p style="font-size:12px;color:var(--text-muted);margin:8px 0">Пути, которые Defender не отметил, но корреляция/AI выявила</p>
    <input type="file" id="protectFile" style="margin:8px 0">
    <textarea id="protectPaths" placeholder="C:\path\to\file.exe&#10;C:\Users\...\suspicious.dll" style="width:100%;height:100px;background:var(--bg-dark);border:1px solid var(--border);border-radius:8px;color:var(--text);padding:10px;margin:8px 0;font-family:monospace"></textarea>
    <button class="btn" onclick="uploadAnalyze()">Анализировать</button>
    <div id="protectOut" class="log-box" style="margin-top:12px;min-height:60px"></div>
  </div>
  <div class="settings-card">
    <h4>Пути, отмеченные AI/корреляцией</h4>
    <div id="flaggedList" class="activity-list" style="max-height:200px"></div>
    <button class="btn" style="margin-top:8px" onclick="refreshFlagged()">Обновить</button>
  </div>
</div>

<!-- QUARANTINE -->
<div id="panel-quarantine" class="section-panel">
  <div class="settings-card">
    <h4>Проверить файлы на VT (по хэшам)</h4>
    <p style="font-size:12px;color:var(--text-muted)">Выберите файл — из него извлекут хэши, проверят в VirusTotal и добавят в whitelist/blacklist.</p>
    <div style="margin:8px 0">
      <strong>Scan:</strong>
      <div id="vtScanFiles" style="display:flex;flex-wrap:wrap;gap:6px;margin:4px 0"></div>
    </div>
    <div style="margin:8px 0">
      <strong>EDR:</strong>
      <div id="vtEdrFiles" style="display:flex;flex-wrap:wrap;gap:6px;margin:4px 0"></div>
    </div>
    <div id="vtCheckLog" class="log-box" style="min-height:80px;margin-top:8px;font-size:11px"></div>
  </div>
  <div class="settings-card">
    <h4>Whitelist / Blacklist хэшей</h4>
    <p style="font-size:12px;color:var(--text-muted)">Проверенные VT: чисто → whitelist, угроза → blacklist. Повторно не проверяются.</p>
    <div id="hashlistSummary">White: 0 | Black: 0</div>
    <button class="btn" style="margin-top:8px" onclick="refreshHashlist()">Обновить</button>
  </div>
  <div class="settings-card">
    <h4>VirusTotal API</h4>
    <p style="font-size:12px;color:var(--text-muted)">Ключ для проверки хэшей (score &gt; 0)</p>
    <input type="password" id="vtkey" placeholder="VT API key">
    <button class="btn" style="margin-top:8px" onclick="saveVTKey()">Сохранить ключ</button>
    <p style="font-size:11px;margin-top:8px;color:var(--text-muted)">Бесплатно: virustotal.com/gui/my-apikey</p>
  </div>
</div>

<!-- UPDATE -->
<div id="panel-update" class="section-panel">
  <div class="settings-card">
    <h4>Обновления системы и драйверов</h4>
    <div class="actions" style="margin-top:12px">
      <button class="btn" onclick="run('update',this)">Update (winget, Defender)</button>
      <button class="btn" onclick="run('driver-install',this)">Driver Install</button>
      <button class="btn" onclick="run('driver-auto',this)">Driver Auto</button>
    </div>
    <p style="font-size:12px;color:var(--text-muted);margin-top:12px">Driver Install/Auto — интерактивны, лучше из терминала: doctor driver-install</p>
  </div>
  <div class="log-box" id="outUpdate" style="min-height:100px">Вывод команд Update...</div>
</div>

<!-- SETTINGS -->
<div id="panel-settings" class="section-panel">
  <div class="settings-card">
    <h4>OpenAI API Key</h4>
    <input type="password" id="apikey" placeholder="sk-...">
    <button class="btn" style="margin-top:8px" onclick="setKey()">Сохранить</button>
  </div>
  <div class="settings-card">
    <h4>VirusTotal API Key</h4>
    <input type="password" id="vtkeySettings" placeholder="VT key для Quarantine">
    <button class="btn" style="margin-top:8px" onclick="saveVTKeyFromSettings()">Сохранить</button>
  </div>
</div>

</div>
</div>
</div>
</div>

<div class="modal-overlay" id="modalOverlay">
  <div class="modal-box">
    <div class="spinner"></div>
    <h3 id="modalTitle">Выполняется...</h3>
    <p id="modalMsg">Ориентировочно 30–60 сек. Подождите.</p>
  </div>
</div>

<script>
const out=document.getElementById('out');
const progressRing=document.getElementById('progressRing');
const progressPercent=document.getElementById('progressPercent');
const threatsCount=document.getElementById('threatsCount');
const statusBadge=document.getElementById('statusBadge');
const greeting=document.getElementById('greeting');
const modalOverlay=document.getElementById('modalOverlay');
const modalTitle=document.getElementById('modalTitle');
const modalMsg=document.getElementById('modalMsg');

const cmdTimes = { scan: '30-60 сек', plan: '5-15 сек', fix: '20-40 сек', avscan: '1-5 мин', analyze: '30-90 сек', 'driver-install': 'интерактивно', 'driver-auto': 'интерактивно', update: '1-3 мин' };

function showModal(title, msg) {
  modalTitle.textContent = title || 'Выполняется...';
  modalMsg.textContent = msg || 'Подождите.';
  modalOverlay.classList.add('visible');
}
function hideModal() { modalOverlay.classList.remove('visible'); }
function setProgress(p){ if(progressRing){ progressRing.style.setProperty('--p',p); progressPercent.textContent=p+'%'; }}

function setBtnWorking(btn, working) {
  if (!btn) return;
  document.querySelectorAll('.btn').forEach(b=>b.classList.remove('working'));
  if (working) btn.classList.add('working');
}

document.querySelectorAll('.nav-item').forEach(el=>{
  el.addEventListener('click',()=>{
    const sec=el.getAttribute('data-section');
    document.querySelectorAll('.nav-item').forEach(x=>x.classList.remove('active'));
    document.querySelectorAll('.section-panel').forEach(x=>x.classList.remove('active'));
    el.classList.add('active');
    const panel=document.getElementById('panel-'+sec);
    if(panel) panel.classList.add('active');
    if(sec==='quarantine'){ refreshQuarantine(); refreshHashlist(); refreshVTFileList(); }
    if(sec==='protect') refreshFlagged();
  });
});

async function refreshStatus(){
  try{
    const r=await fetch('/api/status');
    const d=await r.json();
    greeting.textContent='Привет, '+(d.host||'User')+'!';
    statusBadge.textContent=d.agent?'Agent ✓':'Stay Safe ✓';
    statusBadge.className='badge badge-safe';
  }catch(e){ statusBadge.textContent='Offline'; statusBadge.className='badge'; }
}

async function refreshThreats(){
  try{
    const r=await fetch('/api/quick-check');
    const d=await r.json();
    const n=d.incidents||0;
    threatsCount.textContent=n+' угроз обнаружено';
    setProgress(Math.min(100, (d.events||0)/10));
  }catch(e){ threatsCount.textContent='—'; }
}

async function refreshHistory(){
  try{
    const r=await fetch('/api/scan-history');
    const arr=await r.json();
    const html=arr.slice(-7).map((x,i)=>'<span class="hist-date'+(i===arr.length-1?' active':'')+'">'+x.date+'</span>').join('');
    document.getElementById('historyDates').innerHTML=html||'<span class="hist-date">Нет сканов</span>';
  }catch(e){ document.getElementById('historyDates').innerHTML='<span class="hist-date">—</span>'; }
}

function getOutput(){
  const p=document.querySelector('.section-panel.active');
  if(p&&p.id==='panel-update') return document.getElementById('outUpdate');
  return out;
}

async function run(cmd, btn, auto){
  const t = cmdTimes[cmd] || 'неизвестно';
  showModal(cmd + ' выполняется...', 'Ориентировочно: ' + t);
  setBtnWorking(btn, true);
  try{
    const r=await fetch('/api/run?cmd='+encodeURIComponent(cmd)+(auto?'&auto=1':''));
    getOutput().textContent=await r.text();
    setProgress(100);
    refreshThreats(); refreshHistory();
  }catch(e){ getOutput().textContent='Ошибка: '+e.message; }
  hideModal(); setBtnWorking(btn, false);
}

async function analyze(btn){
  showModal('Analyze AI...', 'Корреляция + AI объяснения. Ориентировочно 30-90 сек.');
  setBtnWorking(btn, true);
  try{
    const r=await fetch('/api/analyze');
    out.textContent=await r.text();
    setProgress(100);
    refreshThreats(); refreshHistory();
  }catch(e){ out.textContent='Ошибка: '+e.message; }
  hideModal(); setBtnWorking(btn, false);
}

async function agentRun(btn){
  showModal('Agent...', 'Запуск EDR-агента');
  setBtnWorking(btn, true);
  try{
    const r=await fetch('/api/agent');
    out.textContent=await r.text();
    refreshStatus();
  }catch(e){ out.textContent='Ошибка: '+e.message; }
  hideModal(); setBtnWorking(btn, false);
}

async function setKey(){
  const key=document.getElementById('apikey').value;
  if(!key){ alert('Введите ключ'); return; }
  showModal('Сохранение...', '');
  try{
    const fd=new FormData(); fd.append('key',key);
    await fetch('/api/ai-key',{method:'POST',body:fd});
    alert('OpenAI ключ сохранён');
  }catch(e){ alert('Ошибка: '+e.message); }
  hideModal();
}

async function latestScan(btn){
  showModal('Latest Scan...', '');
  setBtnWorking(btn, true);
  try{
    const r=await fetch('/api/latest-scan');
    out.textContent=await r.text();
  }catch(e){ out.textContent='Ошибка: '+e.message; }
  hideModal(); setBtnWorking(btn, false);
}

async function uploadAnalyze(){
  const paths=document.getElementById('protectPaths').value;
  const file=document.getElementById('protectFile').files[0];
  showModal('Анализ...', '');
  try{
    const fd=new FormData();
    if(file) fd.append('file', file);
    fd.append('paths', paths);
    const r=await fetch('/api/upload-analyze', {method:'POST', body:fd});
    document.getElementById('protectOut').textContent=await r.text();
    refreshFlagged();
  }catch(e){ document.getElementById('protectOut').textContent='Ошибка: '+e.message; }
  hideModal();
}

async function refreshFlagged(){
  try{
    const r=await fetch('/api/flagged-paths');
    const arr=await r.json();
    const list=document.getElementById('flaggedList');
    if(list) list.innerHTML=arr.length?arr.map(x=>'<div>'+escapeHtml(x.path)+' ['+x.severity+']</div>').join(''):'<div>Нет данных. Запустите Analyze.</div>';
  }catch(e){}
}

async function refreshHashlist(){
  try{
    const r=await fetch('/api/hashlist');
    const d=await r.json();
    const el=document.getElementById('hashlistSummary');
    if(el) el.textContent='White: '+d.whitelist.length+' | Black: '+d.blacklist.length;
  }catch(e){}
}

async function refreshVTFileList(){
  try{
    const r=await fetch('/api/vt-file-list');
    const d=await r.json();
    const scanEl=document.getElementById('vtScanFiles');
    const edrEl=document.getElementById('vtEdrFiles');
    if(scanEl){
      scanEl.innerHTML=(d.scans||[]).map(x=>'<button class="btn vt-file-btn" data-path="'+escapeAttr(x.path)+'">'+escapeHtml(x.name)+'</button>').join('')||'<span style="color:var(--text-muted)">Нет scan_*.json</span>';
    }
    if(edrEl){
      edrEl.innerHTML=(d.edr||[]).map(x=>'<button class="btn vt-file-btn" data-path="'+escapeAttr(x.path)+'">'+escapeHtml(x.name)+'</button>').join('')||'<span style="color:var(--text-muted)">Нет edr_*.jsonl</span>';
    }
    document.querySelectorAll('.vt-file-btn').forEach(btn=>{
      btn.onclick=function(){ checkFileVT(this.getAttribute('data-path')); };
    });
  }catch(e){}
}

function escapeAttr(s){
  return String(s).replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

async function checkFileVT(path){
  const logEl=document.getElementById('vtCheckLog');
  if(logEl) logEl.textContent='Проверка...';
  try{
    const fd=new FormData();
    fd.append('path',path);
    const r=await fetch('/api/check-file-vt',{method:'POST',body:fd});
    const text=await r.text();
    if(logEl) logEl.textContent=text;
    refreshHashlist();
  }catch(e){
    if(logEl) logEl.textContent='Ошибка: '+e.message;
  }
}

async function refreshQuarantine(){
  try{
    const r=await fetch('/api/quarantine-hashes');
    const arr=await r.json();
    const list=document.getElementById('quarantineList');
    if(list) list.innerHTML=arr.length?arr.map(x=>'<div>'+escapeHtml(x.name)+'</div>').join(''):'<div>Карантин пуст</div>';
  }catch(e){}
}

async function saveVTKey(){
  const key=document.getElementById('vtkey').value;
  if(!key){ alert('Введите VT ключ'); return; }
  const fd=new FormData(); fd.append('key',key);
  await fetch('/api/vt-key',{method:'POST',body:fd});
  alert('VirusTotal ключ сохранён');
}

async function saveVTKeyFromSettings(){
  const key=document.getElementById('vtkeySettings').value;
  if(!key){ alert('Введите VT ключ'); return; }
  const fd=new FormData(); fd.append('key',key);
  await fetch('/api/vt-key',{method:'POST',body:fd});
  alert('Сохранено');
}

async function refreshActivity(){
  try{
    const r=await fetch('/api/events-tail');
    const arr=await r.json();
    document.getElementById('activityList').innerHTML=arr.map(x=>'<div>'+escapeHtml(x)+'</div>').join('')||'<div>Нет событий</div>';
  }catch(e){ document.getElementById('activityList').innerHTML='<div>—</div>'; }
}
function escapeHtml(s){ const d=document.createElement('div'); d.textContent=s; return d.innerHTML; }

refreshStatus(); refreshThreats(); refreshHistory(); refreshActivity();
</script>
</body>
</html>
`
