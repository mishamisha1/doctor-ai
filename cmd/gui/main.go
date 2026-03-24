package main

import (
	"bufio"
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
	"doctor-ai/internal/virustotal"
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
	baseDir = resolveBaseDir()
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

func isInteractiveCommand(cmd string) bool {
	switch strings.ToLower(strings.TrimSpace(cmd)) {
	case "driver-install", "driver-auto":
		return true
	default:
		return false
	}
}

func runPS1(cmd string, auto bool) (string, error) {
	return collector.RunDoctorPS1WithOutput(collector.PS1Args{
		PS1Path: ps1Path, Cmd: cmd, PolicyPath: policyPath, Auto: auto, WorkingDir: baseDir,
	})
}

func autoEnsureSysmonOnStartup() {
	cfg, err := agent.LoadConfig(agentPath)
	if err != nil {
		log.Printf("WARN: startup-check config load failed: %v", err)
		return
	}
	desc := runner.CommandDescriptions[cmd]
	if isInteractiveCommand(cmd) {
		err := collector.StartDoctorPS1InteractiveTerminal(collector.PS1Args{PS1Path: ps1Path, Cmd: cmd, PolicyPath: policyPath, Auto: auto, WorkingDir: baseDir})
		result := desc + "\n\n--- режим запуска ---\nИнтерактивная команда запущена в отдельном терминале."
		if err != nil {
			result += "\n[ОШИБКА] " + err.Error()
		} else {
			result += "\n[OK]"
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(result))
		return
	}
	out, err := runPS1(cmd, auto)
	result := desc + "\n\n--- вывод ---\n" + out
	if err != nil {
		result += "\n[ОШИБКА] " + err.Error()
	} else {
		result += "\n[OK]"
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

type startupCheck struct {
	Admin        bool   `json:"admin"`
	SysmonExe    bool   `json:"sysmonExe"`
	SysmonConfig bool   `json:"sysmonConfig"`
	LogsDir      bool   `json:"logsDir"`
	ConfigDir    bool   `json:"configDir"`
	OpenAIKey    bool   `json:"openaiKey"`
	VTKey        bool   `json:"vtKey"`
	Message      string `json:"message"`
}

func handleStartupCheck(w http.ResponseWriter, r *http.Request) {
	s := startupCheck{}
	s.LogsDir = pathExists(filepath.Join(baseDir, "logs"))
	s.ConfigDir = pathExists(filepath.Join(baseDir, "configs"))
	s.SysmonExe = pathExists(filepath.Join(baseDir, "db", "tools", "sysmon", "Sysmon64.exe"))
	s.SysmonConfig = pathExists(filepath.Join(baseDir, "db", "sysmon", "sysmonconfig.xml"))
	s.OpenAIKey = pathExists(filepath.Join(logsDir, ".openai_key"))
	s.VTKey = pathExists(filepath.Join(logsDir, ".vt_key"))
	s.Admin = isAdminWindows()
	if !s.Admin {
		s.Message = "Запустите от администратора для обязательной установки Sysmon"
	} else if !s.SysmonExe {
		s.Message = "Sysmon.exe отсутствует: запуск Agent выполнит обязательную установку"
	} else {
		s.Message = "Готово к полноценному режиму (Sysmon обязателен)"
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s)
}

func pathExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func isAdminWindows() bool {
	if runtime.GOOS != "windows" {
		return false
	}
	cmd := exec.Command("cmd", "/C", "net", "session")
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
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

func handleQuickProtect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	step := strings.TrimSpace(r.FormValue("step"))
	if step == "" {
		http.Error(w, "missing step", 400)
		return
	}
	switch step {
	case "1":
		handleAgent(w, r)
	case "2":
		handleAnalyze(w, r)
	case "3":
		handleAutoProtect(w, r)
	default:
		http.Error(w, "unknown step", 400)
	}
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
	if err := ensureRequiredSysmon(cfg); err != nil {
		log.Printf("WARN: sysmon ensure on startup failed: %v", err)
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

func ensureRequiredSysmon(cfg *agent.Config) error {
	if runtime.GOOS != "windows" {
		return nil
	}
	if !pathExists(cfg.Sysmon.ExePath) {
		if err := ensureSysmonExecutable(); err != nil {
			return err
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

type logHealth struct {
	Path         string `json:"path"`
	Exists       bool   `json:"exists"`
	SizeBytes    int64  `json:"sizeBytes"`
	LineCount    int    `json:"lineCount"`
	Oldest       string `json:"oldest"`
	Newest       string `json:"newest"`
	RetentionHrs int    `json:"retentionHours"`
	MaxLines     int    `json:"maxLines"`
}

func readLogHealth(path string, retentionHours, maxLines int) (logHealth, error) {
	h := logHealth{Path: path, RetentionHrs: retentionHours, MaxLines: maxLines}
	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return h, nil
		}
		return h, err
	}
	h.Exists = true
	h.SizeBytes = fi.Size()

	f, err := os.Open(path)
	if err != nil {
		return h, err
	}
	defer f.Close()

	type tsOnly struct {
		Timestamp time.Time `json:"ts"`
	}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		h.LineCount++
		var t tsOnly
		if err := json.Unmarshal([]byte(line), &t); err != nil || t.Timestamp.IsZero() {
			continue
		}
		if h.Oldest == "" {
			h.Oldest = t.Timestamp.Format(time.RFC3339)
		}
		h.Newest = t.Timestamp.Format(time.RFC3339)
	}
	if err := sc.Err(); err != nil {
		return h, err
	}
	return h, nil
}

func handleLogHealth(w http.ResponseWriter, r *http.Request) {
	cfg, err := agent.LoadConfig(agentPath)
	if err != nil {
		http.Error(w, "config: "+err.Error(), 500)
		return
	}
	h, err := readLogHealth(cfg.Output.Path, cfg.Output.RetentionHours, cfg.Output.MaxLines)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h)
}

func handleLogCompact(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	agentMu.Lock()
	running := agentRunning
	agentMu.Unlock()
	if running {
		http.Error(w, "Остановите/дождитесь завершения agent перед compaction", 409)
		return
	}
	cfg, err := agent.LoadConfig(agentPath)
	if err != nil {
		http.Error(w, "config: "+err.Error(), 500)
		return
	}
	before, _ := readLogHealth(cfg.Output.Path, cfg.Output.RetentionHours, cfg.Output.MaxLines)
	wr, err := agent.NewWriter(cfg.Output.Path, cfg.Output.RetentionHours, cfg.Output.MaxLines)
	if err != nil {
		http.Error(w, "compact: "+err.Error(), 500)
		return
	}
	_ = wr.Close()
	after, _ := readLogHealth(cfg.Output.Path, cfg.Output.RetentionHours, cfg.Output.MaxLines)
	msg := fmt.Sprintf("Compaction OK\nBefore: lines=%d size=%d\nAfter: lines=%d size=%d", before.LineCount, before.SizeBytes, after.LineCount, after.SizeBytes)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(msg))
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
	var last error
	for i := 0; i < 3; i++ {
		if err := agent.EnsureSysmon(cfg.Sysmon.ExePath, cfg.Sysmon.ConfigPath); err != nil {
			last = err
			time.Sleep(2 * time.Second)
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
	if last != nil {
		return last
	}
	return fmt.Errorf("sysmon ensure failed")
}

type flaggedItem struct {
	Path     string `json:"path"`
	Severity string `json:"severity"`
	Reasons  string `json:"reasons"`
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

func handleCustomScan(w http.ResponseWriter, r *http.Request) {
	roots := scanner.DefaultRoots()
	if len(roots) == 0 {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("Smart Scan: не найдены каталоги для локального сканирования."))
		return
	}
	res, err := scanner.ScanQuick(roots, 50)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(scanner.FormatResult(res)))
}

func handleAutoProtect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	key := scanner.LoadOpenAIKey(logsDir)
	incRes, _ := runner.RunAnalyze(r.Context(), runner.AnalyzeOpts{InPath: filepath.Join(logsDir, "edr_events.jsonl"), LogsDir: logsDir})
	incidentPaths := make([]string, 0)
	if incRes != nil {
		for _, it := range collectFlaggedFromIncidents(incRes.Incidents) {
			incidentPaths = append(incidentPaths, it.Path)
		}
	}
	res, err := scanner.RunAutoprotect(r.Context(), scanner.ProtectConfig{
		Roots:         scanner.DefaultRoots(),
		IncidentPaths: incidentPaths,
		MaxFindings:   50,
		MinScore:      70,
		EnableAI:      key != "",
		OpenAIKey:     key,
		AIModel:       "gpt-5-nano",
		QuarantineDir: filepath.Join(baseDir, "quarantine"),
	})
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(scanner.FormatProtectResult(res)))
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
.log-health { display:grid; grid-template-columns: repeat(auto-fit,minmax(140px,1fr)); gap:10px; margin-top:10px; }
.log-health .metric { background: var(--bg-dark); border:1px solid var(--border); border-radius:10px; padding:10px; }
.metric .k { color: var(--text-muted); font-size:11px; }
.metric .v { margin-top:4px; font-family:'JetBrains Mono', monospace; font-size:12px; }
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
  <div class="nav-item" data-section="lab"><span class="icon">🧪</span> Lab</div>
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
    <button class="btn" onclick="humanReport(this)">Human Report</button>
    <button class="btn btn-primary" data-cmd="smart-scan" onclick="customScan(this)">Smart Scan</button>
    <button class="btn btn-danger" data-cmd="knight-mode" onclick="knightMode(this)">Knight Mode</button>
    <button class="btn" data-cmd="agent" onclick="agentRun(this)">Agent</button>
    <button class="btn" data-cmd="latestScan" onclick="latestScan(this)">Latest Scan</button>
  </div>
  <div class="log-box" id="out">Scan: телеметрия. Plan: план. Fix: применить. Analyze: EDR+AI.</div>

  <div class="settings-card">
    <h4>Quick Protect (3 шага)</h4>
    <p style="font-size:12px;color:var(--text-muted)">Для обычного пользователя: 1) Agent, 2) Analyze, 3) Knight Mode.</p>
    <div style="display:flex;gap:8px;flex-wrap:wrap">
      <button class="btn" onclick="quickProtect('1',this)">Шаг 1: Start Agent</button>
      <button class="btn" onclick="quickProtect('2',this)">Шаг 2: Analyze</button>
      <button class="btn btn-danger" onclick="quickProtect('3',this)">Шаг 3: Knight Mode</button>
    </div>
    <div id="quickProtectOut" class="log-box" style="min-height:80px;margin-top:10px">Готово к запуску шагов.</div>
  </div>
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


<!-- LAB -->
<div id="panel-lab" class="section-panel">
  <div class="settings-card">
    <h4>Lab / Simulation</h4>
    <p style="font-size:12px;color:var(--text-muted)">Сгенерируйте синтетический поток EDR-событий, запустите корреляцию и посмотрите timeline инцидентов без консоли.</p>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:8px">
      <select id="labScenario" style="padding:10px;background:var(--bg-dark);border:1px solid var(--border);border-radius:8px;color:var(--text)">
        <option value="mixed">mixed</option>
        <option value="malicious">malicious</option>
        <option value="benign">benign</option>
      </select>
      <input id="labCount" type="number" min="1" max="500" value="30" style="width:110px;padding:10px;background:var(--bg-dark);border:1px solid var(--border);border-radius:8px;color:var(--text)">
      <button class="btn btn-primary" onclick="labGenerate(this)">Generate stream</button>
      <button class="btn" onclick="labAnalyze(this)">Run Analyze</button>
      <button class="btn" onclick="labTimeline(this)">Show timeline</button>
    </div>
  </div>
  <div class="log-box" id="labOut" style="min-height:120px">Lab output...</div>
  <div class="settings-card">
    <h4>Incidents timeline</h4>
    <div id="labTimelineBox" class="log-box" style="min-height:160px">Нет данных.</div>
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
      <button class="btn" onclick="refreshDriverReport()">Driver Report</button>
    </div>
    <p style="font-size:12px;color:var(--text-muted);margin-top:12px">Driver Install/Auto — интерактивны, запускаются в отдельном терминале.</p>
  </div>
  <div class="settings-card">
    <h4>AI Driver Assistant</h4>
    <textarea id="driverIssue" placeholder="Опишите проблему: экран мигает, звук не работает, wifi отваливается..." style="width:100%;height:90px;background:var(--bg-dark);border:1px solid var(--border);border-radius:8px;color:var(--text);padding:10px;font-family:inherit"></textarea>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:10px">
      <button class="btn btn-primary" onclick="askDriverAI(this)">AI: подобрать драйвер</button>
      <button class="btn btn-danger" onclick="applyDriverAI(this)">Подтвердить и применить</button>
    </div>
    <div id="driverAIPlan" class="log-box" style="min-height:80px;margin-top:10px">AI план пока не сформирован.</div>
  </div>
  <div class="settings-card">
    <h4>Подробный отчёт по драйверам</h4>
    <div id="driverReport" class="log-box" style="min-height:180px">Нет данных.</div>
  </div>
  <div class="log-box" id="outUpdate" style="min-height:100px">Вывод команд Update...</div>
</div>

<!-- SETTINGS -->
<div id="panel-settings" class="section-panel">

  <div class="settings-card">
    <h4>Startup / Portable Check</h4>
    <p style="font-size:12px;color:var(--text-muted)">Проверка готовности этого ПК: права, ключи, пути, Sysmon assets.</p>
    <div id="startupCheckBox" class="log-box" style="min-height:110px">Проверка...</div>
    <button class="btn" style="margin-top:8px" onclick="refreshStartupCheck()">Обновить проверку</button>
  </div>
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
  <div class="settings-card">
    <h4>Log Hygiene (EDR)</h4>
    <p style="font-size:12px;color:var(--text-muted)">Контроль размера и "свежести" <code>edr_events.jsonl</code>. Помогает не тянуть старые инциденты.</p>
    <div class="log-health" id="logHealthBox">
      <div class="metric"><div class="k">Lines</div><div class="v" id="logLines">—</div></div>
      <div class="metric"><div class="k">Size</div><div class="v" id="logSize">—</div></div>
      <div class="metric"><div class="k">Oldest</div><div class="v" id="logOldest">—</div></div>
      <div class="metric"><div class="k">Newest</div><div class="v" id="logNewest">—</div></div>
    </div>
    <div style="display:flex;gap:8px;margin-top:10px;flex-wrap:wrap">
      <button class="btn" onclick="refreshLogHealth()">Обновить метрики</button>
      <button class="btn btn-danger" onclick="compactLogsNow(this)">Очистить старые логи сейчас</button>
    </div>
    <div id="logCompactOut" class="log-box" style="min-height:60px;margin-top:10px">Нет данных.</div>
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
let driverPlanCommand='';

const cmdTimes = { scan: '30-60 сек', plan: '5-15 сек', fix: '20-40 сек', avscan: '1-5 мин', analyze: '30-90 сек', 'smart-scan':'20-60 сек', 'knight-mode':'30-90 сек', 'lab-generate':'5-10 сек', 'lab-analyze':'10-20 сек', 'lab-timeline':'3-5 сек', 'quick-protect':'10-120 сек', 'driver-install': 'интерактивно', 'driver-auto': 'интерактивно', 'driver-ai':'20-60 сек', update: '1-3 мин' };

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
    if(sec==='settings'){ refreshLogHealth(); refreshStartupCheck(); }
    if(sec==='update') refreshDriverReport();
    if(sec==='lab') labTimeline();
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

async function customScan(btn){
  showModal('Smart Scan...', 'Локальный эвристический скан подозрительных файлов.');
  setBtnWorking(btn, true);
  try{
    const r=await fetch('/api/custom-scan');
    out.textContent=await r.text();
  }catch(e){ out.textContent='Ошибка: '+e.message; }
  hideModal(); setBtnWorking(btn, false);
}

async function knightMode(btn){
  showModal('Knight Mode...', 'Проактивная защита: локальная эвристика + AI verdict + авто-реакция.');
  setBtnWorking(btn, true);
  try{
    const r=await fetch('/api/auto-protect',{method:'POST'});
    out.textContent=await r.text();
    refreshThreats();
  }catch(e){ out.textContent='Ошибка: '+e.message; }
  hideModal(); setBtnWorking(btn, false);
}

async function labGenerate(btn){
  showModal('Lab Generate...', 'Генерация синтетического EDR-потока.');
  setBtnWorking(btn, true);
  try{
    const scenario=document.getElementById('labScenario').value;
    const count=document.getElementById('labCount').value||'30';
    const fd=new FormData();
    fd.append('scenario', scenario);
    fd.append('count', count);
    const r=await fetch('/api/lab-generate',{method:'POST',body:fd});
    const text=await r.text();
    document.getElementById('labOut').textContent=text;
    refreshThreats();
  }catch(e){ document.getElementById('labOut').textContent='Ошибка: '+e.message; }
  hideModal(); setBtnWorking(btn, false);
}

async function labAnalyze(btn){
  showModal('Lab Analyze...', 'Запуск корреляции по сгенерированному потоку.');
  setBtnWorking(btn, true);
  try{
    const r=await fetch('/api/lab-analyze',{method:'POST'});
    const text=await r.text();
    document.getElementById('labOut').textContent=text;
    await labTimeline();
    refreshThreats();
  }catch(e){ document.getElementById('labOut').textContent='Ошибка: '+e.message; }
  hideModal(); setBtnWorking(btn, false);
}

async function labTimeline(btn){
  if(btn) setBtnWorking(btn, true);
  try{
    const r=await fetch('/api/lab-timeline');
    if(!r.ok) throw new Error(await r.text());
    const arr=await r.json();
    let txt='Incidents: '+arr.length+'\n\n';
    arr.forEach((x,i)=>{
      txt += (i+1)+') ['+(x.severity||'n/a')+'] score='+x.score+'\n';
      txt += '   '+x.start+' -> '+x.end+'\n';
      (x.reasons||[]).slice(0,3).forEach(r=>{ txt += '   - '+r+'\n'; });
      txt += '\n';
    });
    document.getElementById('labTimelineBox').textContent=txt;
  }catch(e){ document.getElementById('labTimelineBox').textContent='Ошибка timeline: '+e.message; }
  if(btn) setBtnWorking(btn, false);
}

async function quickProtect(step, btn){
  showModal('Quick Protect...', 'Выполняем шаг '+step+' из 3');
  setBtnWorking(btn, true);
  try{
    const fd=new FormData(); fd.append('step', step);
    const r=await fetch('/api/quick-protect',{method:'POST',body:fd});
    const text=await r.text();
    document.getElementById('quickProtectOut').textContent=text;
    out.textContent=text;
    refreshStatus(); refreshThreats();
  }catch(e){ document.getElementById('quickProtectOut').textContent='Ошибка: '+e.message; }
  hideModal(); setBtnWorking(btn, false);
}

async function humanReport(btn){
  showModal('Human Report...', 'Собираем понятный отчёт по инцидентам.');
  setBtnWorking(btn, true);
  try{
    const r=await fetch('/api/human-report');
    out.textContent=await r.text();
  }catch(e){ out.textContent='Ошибка: '+e.message; }
  hideModal(); setBtnWorking(btn, false);
}

async function refreshStartupCheck(){
  try{
    const r=await fetch('/api/startup-check');
    if(!r.ok) throw new Error(await r.text());
    const d=await r.json();
    const yes=v=>v?'OK':'NO';
    let txt='Admin: '+yes(d.admin)+'\n';
    txt+='Logs dir: '+yes(d.logsDir)+'\n';
    txt+='Configs dir: '+yes(d.configDir)+'\n';
    txt+='Sysmon exe: '+yes(d.sysmonExe)+'\n';
    txt+='Sysmon config: '+yes(d.sysmonConfig)+'\n';
    txt+='OpenAI key: '+yes(d.openaiKey)+'\n';
    txt+='VT key: '+yes(d.vtKey)+'\n\n';
    txt+=d.message||'';
    document.getElementById('startupCheckBox').textContent=txt;
  }catch(e){
    document.getElementById('startupCheckBox').textContent='Ошибка проверки: '+e.message;
  }
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

async function refreshDriverReport(){
  try{
    const r=await fetch('/api/driver-report');
    if(!r.ok) throw new Error(await r.text());
    const d=await r.json();
    let txt='Installed drivers: '+(d.installed||[]).length+'\n';
    txt+='Problematic/unsigned: '+(d.problematic||[]).length+'\n\n';
    (d.problematic||[]).slice(0,20).forEach((x,i)=>{
      txt += (i+1)+') '+(x.deviceName||'unknown')+' | '+(x.provider||'')+' | '+(x.version||'')+' | inf='+ (x.inf||'') +'\n';
    });
    txt += '\nDownloaded/updated packages from logs: '+(d.downloaded||[]).length+'\n';
    (d.downloaded||[]).slice(0,10).forEach((x,i)=>{
      txt += (i+1)+') '+x.folder+'\n';
      if(x.provenance) txt += '   provenance: '+x.provenance.replace(/\n/g,' | ')+'\n';
    });
    document.getElementById('driverReport').textContent=txt;
  }catch(e){
    document.getElementById('driverReport').textContent='Ошибка отчёта: '+e.message;
  }
}

async function askDriverAI(btn){
  const issue=document.getElementById('driverIssue').value.trim();
  if(!issue){ alert('Опишите проблему'); return; }
  showModal('AI Driver Assistant...', 'Анализ симптомов и подбор команды.');
  setBtnWorking(btn,true);
  try{
    const fd=new FormData(); fd.append('issue',issue);
    const r=await fetch('/api/driver-ai-plan',{method:'POST',body:fd});
    const txt=await r.text();
    if(!r.ok) throw new Error(txt);
    const p=JSON.parse(txt);
    driverPlanCommand=p.command||'';
    document.getElementById('driverAIPlan').textContent='Command: '+(p.command||'none')+'\nConfidence: '+(p.confidence||0)+'\nTarget: '+(p.target_hint||'')+'\nReason: '+(p.reason||'');
  }catch(e){
    document.getElementById('driverAIPlan').textContent='AI ошибка: '+e.message;
    driverPlanCommand='';
  }
  hideModal(); setBtnWorking(btn,false);
}

async function applyDriverAI(btn){
  if(!driverPlanCommand || driverPlanCommand==='none'){ alert('Сначала получите AI план'); return; }
  if(!confirm('Применить AI-план и запустить '+driverPlanCommand+' ?')) return;
  showModal('Применение AI плана...', 'Запускаем интерактивную установку драйвера.');
  setBtnWorking(btn,true);
  try{
    const fd=new FormData(); fd.append('command',driverPlanCommand);
    const r=await fetch('/api/driver-ai-apply',{method:'POST',body:fd});
    const text=await r.text();
    document.getElementById('outUpdate').textContent=text;
  }catch(e){ document.getElementById('outUpdate').textContent='Ошибка: '+e.message; }
  hideModal(); setBtnWorking(btn,false);
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

function humanBytes(n){
  if(!Number.isFinite(n)) return '—';
  const u=['B','KB','MB','GB']; let i=0; let x=n;
  while(x>=1024 && i<u.length-1){x/=1024;i++;}
  return x.toFixed(i===0?0:1)+' '+u[i];
}

async function refreshLogHealth(){
  try{
    const r=await fetch('/api/log-health');
    if(!r.ok) throw new Error(await r.text()||('HTTP '+r.status));
    const d=await r.json();
    document.getElementById('logLines').textContent=d.exists?String(d.lineCount):'0';
    document.getElementById('logSize').textContent=d.exists?humanBytes(d.sizeBytes):'0 B';
    document.getElementById('logOldest').textContent=d.oldest||'—';
    document.getElementById('logNewest').textContent=d.newest||'—';
  }catch(e){
    document.getElementById('logCompactOut').textContent='Ошибка метрик: '+e.message;
  }
}

async function compactLogsNow(btn){
  showModal('Компакция логов...', 'Удаляем устаревшие события и лишние строки.');
  setBtnWorking(btn, true);
  try{
    const r=await fetch('/api/log-compact',{method:'POST'});
    const text=await r.text();
    document.getElementById('logCompactOut').textContent=r.ok?text:('Ошибка compaction: '+text);
    refreshLogHealth();
  }catch(e){
    document.getElementById('logCompactOut').textContent='Ошибка: '+e.message;
  }
  hideModal();
  setBtnWorking(btn, false);
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
function escapeHtml(s){ const d=document.createElement('div'); d.textContent=s; return d.innerHTML; }

refreshStatus(); refreshThreats(); refreshHistory(); refreshActivity(); refreshLogHealth(); refreshDriverReport(); refreshStartupCheck(); labTimeline();
</script>
</body>
</html>
`
