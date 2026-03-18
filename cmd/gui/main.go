package main

import (
	"context"
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
	"strconv"
	"strings"
	"sync"
	"time"

	"doctor-ai/internal/agent"
	aia "doctor-ai/internal/ai"
	"doctor-ai/internal/collector"
	"doctor-ai/internal/model"
	"doctor-ai/internal/runner"
	"doctor-ai/internal/scanner"
	"doctor-ai/internal/simulate"
)

//go:embed embedded/configs
var configsFS embed.FS

var (
	baseDir    string
	ps1Path    string
	policyPath string
	agentPath  string
	logsDir    string
)

func init() {
	self, _ := os.Executable()
	baseDir = filepath.Dir(self)
	_ = os.Chdir(baseDir)
	ps1Path = filepath.Join(baseDir, "configs", "doctor.ps1")
	policyPath = filepath.Join(baseDir, "configs", "policy.json")
	agentPath = filepath.Join(baseDir, "configs", "agent.json")
	logsDir = filepath.Join(baseDir, "logs")

	ensureRuntimeLayout()
	ensureEmbeddedFile(ps1Path, "embedded/configs/doctor.ps1")
	ensureEmbeddedFile(policyPath, "embedded/configs/policy.json")
	ensureEmbeddedFile(agentPath, "embedded/configs/agent.json")
	ensureDefaultSysmonConfig()
	// GUI и Lab ожидают наличие файла телеметрии даже до первого события.
	ensureFileExists(filepath.Join(logsDir, "edr_events.jsonl"))
}

func ensureEmbeddedFile(dstPath, embedPath string) {
	if _, err := os.Stat(dstPath); err == nil {
		return
	}

	if err := os.MkdirAll(filepath.Dir(dstPath), 0755); err != nil {
		log.Printf("WARN: failed to create dir for %s: %v", dstPath, err)
		return
	}
	data, err := fs.ReadFile(configsFS, embedPath)
	if err != nil {
		log.Printf("WARN: failed to read %s: %v", embedPath, err)
		return
	}
	if err := os.WriteFile(dstPath, data, 0644); err != nil {
		log.Printf("WARN: failed to create %s: %v", filepath.Base(dstPath), err)
	}
}

func ensureRuntimeLayout() {
	dirs := []string{
		filepath.Join(baseDir, "configs"),
		filepath.Join(baseDir, "logs"),
		filepath.Join(baseDir, "quarantine"),
		filepath.Join(baseDir, "db"),
		filepath.Join(baseDir, "db", "sysmon"),
		filepath.Join(baseDir, "db", "tools"),
		filepath.Join(baseDir, "db", "tools", "sysmon"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0755); err != nil {
			log.Printf("WARN: failed to create %s: %v", d, err)
		}
	}
}

func ensureDefaultSysmonConfig() {
	cfgPath := filepath.Join(baseDir, "db", "sysmon", "sysmonconfig.xml")
	if _, err := os.Stat(cfgPath); err == nil {
		return
	}
	const defaultCfg = `<Sysmon schemaversion="4.90"><EventFiltering><ProcessCreate onmatch="include"/><NetworkConnect onmatch="include"/><FileCreate onmatch="include"/><RegistryEvent onmatch="include"/></EventFiltering></Sysmon>`
	if err := os.WriteFile(cfgPath, []byte(defaultCfg), 0644); err != nil {
		log.Printf("WARN: failed to create default sysmon config: %v", err)
	}
}

func ensureFileExists(path string) {
	if _, err := os.Stat(path); err == nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		log.Printf("WARN: failed to create parent dir for %s: %v", path, err)
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE, 0644)
	if err != nil {
		log.Printf("WARN: failed to create file %s: %v", path, err)
		return
	}
	_ = f.Close()
}

func ensureSysmonExecutable() error {
	if runtime.GOOS != "windows" {
		return nil
	}
	exePath := filepath.Join(baseDir, "db", "tools", "sysmon", "Sysmon64.exe")
	if _, err := os.Stat(exePath); err == nil {
		return nil
	}
	zipURL := "https://download.sysinternals.com/files/Sysmon.zip"
	zipPath := filepath.Join(baseDir, "db", "tools", "sysmon", "Sysmon.zip")
	ps := fmt.Sprintf("$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';Invoke-WebRequest -UseBasicParsing -Uri %s -OutFile %s -TimeoutSec 25;Expand-Archive -Path %s -DestinationPath %s -Force", psQuote(zipURL), psQuote(zipPath), psQuote(zipPath), psQuote(filepath.Dir(exePath)))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("download/extract sysmon: %w | %s", err, strings.TrimSpace(string(out)))
	}
	_ = os.Remove(zipPath)
	if _, err := os.Stat(exePath); err != nil {
		return fmt.Errorf("sysmon exe missing after extract: %s", exePath)
	}
	return nil
}

func psQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func serverAddr() string {
	if v := strings.TrimSpace(os.Getenv("DOCTOR_GUI_ADDR")); v != "" {
		return v
	}
	return "127.0.0.1:19527"
}

func browserURL(listenAddr string) string {
	host, port, err := strings.Cut(listenAddr, ":")
	if !err || strings.TrimSpace(port) == "" {
		return "http://127.0.0.1:19527"
	}
	host = strings.TrimSpace(host)
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		host = "127.0.0.1"
	}
	return "http://" + host + ":" + port
}

func main() {
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/api/run", handleRun)
	http.HandleFunc("/api/analyze", handleAnalyze)
	http.HandleFunc("/api/agent", handleAgent)
	http.HandleFunc("/api/ai-key", handleAIKey)
	http.HandleFunc("/api/latest-scan", handleLatestScan)
	http.HandleFunc("/api/status", handleStatus)
	http.HandleFunc("/api/startup-check", handleStartupCheck)
	http.HandleFunc("/api/human-report", handleHumanReport)
	http.HandleFunc("/api/quick-protect", handleQuickProtect)
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
	http.HandleFunc("/api/log-health", handleLogHealth)
	http.HandleFunc("/api/log-compact", handleLogCompact)
	http.HandleFunc("/api/custom-scan", handleCustomScan)
	http.HandleFunc("/api/auto-protect", handleAutoProtect)
	http.HandleFunc("/api/auto-protect-preview", handleAutoProtectPreview)
	http.HandleFunc("/api/lab-generate", handleLabGenerate)
	http.HandleFunc("/api/lab-analyze", handleLabAnalyze)
	http.HandleFunc("/api/lab-timeline", handleLabTimeline)
	http.HandleFunc("/api/driver-report", handleDriverReport)
	http.HandleFunc("/api/driver-ai-plan", handleDriverAIPlan)
	http.HandleFunc("/api/driver-ai-apply", handleDriverAIApply)

	addr := serverAddr()
	url := browserURL(addr)
	fmt.Println("Doctor-AI GUI: " + url + " (listen " + addr + ")")
	go bootstrapSysmonOnStartup()
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

func bootstrapSysmonOnStartup() {
	if err := ensureSysmonExecutable(); err != nil {
		log.Printf("WARN: sysmon bootstrap download failed: %v", err)
	}
	autoEnsureSysmonOnStartup()
}

func autoEnsureSysmonOnStartup() {
	cfg, err := agent.LoadConfig(agentPath)
	if err != nil {
		log.Printf("WARN: startup-check config load failed: %v", err)
		return
	}
	if !cfg.Sysmon.Enabled || !cfg.Sysmon.AutoInstall {
		return
	}
	if err := ensureRequiredSysmon(cfg); err != nil {
		log.Printf("WARN: sysmon ensure on startup failed: %v", err)
		return
	}
	log.Printf("INFO: sysmon ensure on startup: OK")
}

func ensureRequiredSysmon(cfg *agent.Config) error {
	if runtime.GOOS != "windows" {
		return nil
	}
	if !pathExists(cfg.Sysmon.ExePath) {
		if err := ensureSysmonExecutable(); err != nil {
			return err
		}
	}
	var last error
	for i := 0; i < 3; i++ {
		if err := agent.EnsureSysmon(cfg.Sysmon.ExePath, cfg.Sysmon.ConfigPath); err != nil {
			last = err
			time.Sleep(2 * time.Second)
			continue
		}
		return nil
	}
	if last != nil {
		return last
	}
	return fmt.Errorf("sysmon ensure failed")
}

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

var (
	agentMu      sync.Mutex
	agentRunning bool
)

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

type flaggedItem struct {
	Path     string `json:"path"`
	Severity string `json:"severity"`
	Reasons  string `json:"reasons"`
}

func collectFlaggedFromIncidents(incidents []*model.Incident) []flaggedItem {
	items := make([]flaggedItem, 0)
	for _, inc := range incidents {
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
				items = append(items, flaggedItem{Path: path, Severity: inc.Severity, Reasons: strings.Join(inc.Reasons, "; ")})
			}
		}
	}
	return items
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
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(collectFlaggedFromIncidents(res.Incidents))
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

func handleLabGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	scenario := strings.TrimSpace(r.FormValue("scenario"))
	if scenario == "" {
		scenario = "mixed"
	}
	count := 30
	if c := strings.TrimSpace(r.FormValue("count")); c != "" {
		if n, err := strconv.Atoi(c); err == nil {
			count = n
		}
	}
	if count < 1 {
		count = 30
	}
	if count > 500 {
		count = 500
	}
	events := simulate.GenerateEvents(scenario, count)
	outPath := filepath.Join(logsDir, "edr_events.jsonl")
	if err := simulate.WriteJSONL(outPath, events); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(fmt.Sprintf("Lab: generated %d events (%s) -> %s", len(events), scenario, outPath)))
}

func handleLabAnalyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	res, err := runner.RunAnalyze(r.Context(), runner.AnalyzeOpts{
		InPath:  filepath.Join(logsDir, "edr_events.jsonl"),
		LogsDir: logsDir,
	})
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(res.Log.String()))
}

func handleLabTimeline(w http.ResponseWriter, r *http.Request) {
	res, err := runner.RunAnalyze(r.Context(), runner.AnalyzeOpts{
		InPath:  filepath.Join(logsDir, "edr_events.jsonl"),
		LogsDir: logsDir,
	})
	if err != nil {
		if os.IsNotExist(err) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]interface{}{})
			return
		}
		http.Error(w, err.Error(), 500)
		return
	}
	type timelineItem struct {
		ID       string   `json:"id"`
		Start    string   `json:"start"`
		End      string   `json:"end"`
		Score    int      `json:"score"`
		Severity string   `json:"severity"`
		Reasons  []string `json:"reasons"`
	}
	items := make([]timelineItem, 0, len(res.Incidents))
	for _, inc := range res.Incidents {
		items = append(items, timelineItem{ID: inc.ID, Start: inc.Start.Format(time.RFC3339), End: inc.End.Format(time.RFC3339), Score: inc.Score, Severity: inc.Severity, Reasons: inc.Reasons})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(items)
}

type driverItem struct {
	DeviceName string `json:"deviceName"`
	Provider   string `json:"provider"`
	Version    string `json:"version"`
	Date       string `json:"date"`
	Inf        string `json:"inf"`
	DeviceID   string `json:"deviceId"`
	Problem    bool   `json:"problem"`
}

type downloadedDriver struct {
	Folder     string `json:"folder"`
	Provenance string `json:"provenance"`
	InstallLog string `json:"installLog"`
}

type driverReport struct {
	Installed   []driverItem       `json:"installed"`
	Problematic []driverItem       `json:"problematic"`
	Downloaded  []downloadedDriver `json:"downloaded"`
}

type driverAIPlan struct {
	Command    string `json:"command"`
	Reason     string `json:"reason"`
	TargetHint string `json:"target_hint"`
	Confidence int    `json:"confidence"`
}

func handleDriverReport(w http.ResponseWriter, r *http.Request) {
	rep := collectDriverReport()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rep)
}

func handleDriverAIPlan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	issue := strings.TrimSpace(r.FormValue("issue"))
	if issue == "" {
		http.Error(w, "missing issue", 400)
		return
	}
	key := scanner.LoadOpenAIKey(logsDir)
	if key == "" {
		http.Error(w, "OpenAI key not set", 400)
		return
	}
	rep := collectDriverReport()
	ctx := r.Context()
	prompt := fmt.Sprintf(`User issue: %s
Problematic drivers: %v
Downloaded driver folders: %v
Return strict JSON only: {"command":"driver-auto|driver-install|none","reason":"...","target_hint":"...","confidence":0-100}`,
		issue, rep.Problematic, rep.Downloaded)
	txt, err := aia.NewClient(key, "gpt-5-nano").Explain(ctx, prompt)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	pl := driverAIPlan{Command: "none", Reason: txt, Confidence: 30}
	if b := extractJSON(txt); b != "" {
		_ = json.Unmarshal([]byte(b), &pl)
	}
	if pl.Command != "driver-auto" && pl.Command != "driver-install" {
		pl.Command = "none"
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(pl)
}

func handleDriverAIApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	cmd := strings.TrimSpace(r.FormValue("command"))
	if cmd != "driver-auto" && cmd != "driver-install" {
		http.Error(w, "unsupported command", 400)
		return
	}
	err := collector.StartDoctorPS1InteractiveTerminal(collector.PS1Args{PS1Path: ps1Path, Cmd: cmd, PolicyPath: policyPath, WorkingDir: baseDir})
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte("AI plan confirmed. Interactive driver flow launched in separate terminal."))
}

func collectDriverReport() driverReport {
	rep := driverReport{Installed: []driverItem{}, Problematic: []driverItem{}, Downloaded: []downloadedDriver{}}
	if runtime.GOOS == "windows" {
		ps := `$drv = Get-CimInstance Win32_PnPSignedDriver | Select-Object FriendlyName, DriverProviderName, DriverVersion, DriverDate, InfName, DeviceID, IsSigned; $dev=Get-CimInstance Win32_PnPEntity | Select-Object Name,PNPDeviceID,ConfigManagerErrorCode; $res=@(); foreach($d in $drv){$err=($dev|Where-Object{$_.PNPDeviceID -eq $d.DeviceID}|Select-Object -First 1).ConfigManagerErrorCode; $prob=($err -ne $null -and [int]$err -ne 0) -or ($d.IsSigned -ne $true); $res += [PSCustomObject]@{deviceName=$d.FriendlyName;provider=$d.DriverProviderName;version=$d.DriverVersion;date=$d.DriverDate;inf=$d.InfName;deviceId=$d.DeviceID;problem=$prob}}; $res|ConvertTo-Json -Depth 4`
		out, err := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps).CombinedOutput()
		if err == nil {
			body := strings.TrimSpace(string(out))
			if strings.HasPrefix(body, "[") {
				_ = json.Unmarshal([]byte(body), &rep.Installed)
			} else if strings.HasPrefix(body, "{") {
				var one driverItem
				if json.Unmarshal([]byte(body), &one) == nil {
					rep.Installed = append(rep.Installed, one)
				}
			}
			for _, it := range rep.Installed {
				if it.Problem {
					rep.Problematic = append(rep.Problematic, it)
				}
			}
		}
	}
	entries, _ := os.ReadDir(logsDir)
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "driver_auto_") {
			continue
		}
		d := filepath.Join(logsDir, e.Name())
		pb, _ := os.ReadFile(filepath.Join(d, "provenance.txt"))
		ib, _ := os.ReadFile(filepath.Join(d, "install.log"))
		rep.Downloaded = append(rep.Downloaded, downloadedDriver{Folder: e.Name(), Provenance: trimStr(string(pb), 600), InstallLog: trimStr(string(ib), 600)})
	}
	return rep
}

func trimStr(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func extractJSON(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
		return s
	}
	start := strings.Index(s, "{")
	end := strings.LastIndex(s, "}")
	if start >= 0 && end > start {
		return s[start : end+1]
	}
	return ""
}
