package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"doctor-ai/internal/agent"
)

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
