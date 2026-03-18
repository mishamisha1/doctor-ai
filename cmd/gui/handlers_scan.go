package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"doctor-ai/internal/collector"
	"doctor-ai/internal/runner"
	"doctor-ai/internal/scanner"
)

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

func handleRun(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	cmd := r.FormValue("cmd")
	auto := r.FormValue("auto") == "1"
	if cmd == "" {
		http.Error(w, "missing cmd", 400)
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
		if os.IsNotExist(err) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Write([]byte("Сначала нажмите Generate stream (или запустите Agent), чтобы создать edr_events.jsonl"))
			return
		}
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

func buildProtectConfig(ctx context.Context, profile string) scanner.ProtectConfig {
	key := scanner.LoadOpenAIKey(logsDir)
	incRes, _ := runner.RunAnalyze(ctx, runner.AnalyzeOpts{InPath: filepath.Join(logsDir, "edr_events.jsonl"), LogsDir: logsDir})
	incidentPaths := make([]string, 0)
	if incRes != nil {
		for _, it := range collectFlaggedFromIncidents(incRes.Incidents) {
			incidentPaths = append(incidentPaths, it.Path)
		}
	}
	pp := resolveKnightProfile(profile)
	return scanner.ProtectConfig{
		Roots:         scanner.DefaultRoots(),
		IncidentPaths: incidentPaths,
		MaxFindings:   pp.MaxFindings,
		MinScore:      pp.MinScore,
		EnableAI:      pp.EnableAI && key != "",
		OpenAIKey:     key,
		AIModel:       pp.AIModel,
		QuarantineDir: filepath.Join(baseDir, "quarantine"),
	}
}

func handleAutoProtectPreview(w http.ResponseWriter, r *http.Request) {
	cfg := buildProtectConfig(r.Context(), r.URL.Query().Get("profile"))
	res, err := scanner.BuildAutoprotectPlan(r.Context(), cfg)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(scanner.FormatProtectPreview(res)))
}

func handleAutoProtect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	cfg := buildProtectConfig(r.Context(), r.FormValue("profile"))
	res, err := scanner.RunAutoprotect(r.Context(), cfg)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(scanner.FormatProtectResult(res)))
}

type knightProfile struct {
	Name        string
	MinScore    int
	MaxFindings int
	EnableAI    bool
	AIModel     string
}

func resolveKnightProfile(name string) knightProfile {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "aggressive":
		return knightProfile{Name: "aggressive", MinScore: 55, MaxFindings: 80, EnableAI: true, AIModel: "gpt-5-nano"}
	case "soft-block", "soft":
		return knightProfile{Name: "soft-block", MinScore: 85, MaxFindings: 40, EnableAI: true, AIModel: "gpt-5-nano"}
	default:
		return knightProfile{Name: "monitor", MinScore: 95, MaxFindings: 30, EnableAI: false, AIModel: "gpt-5-nano"}
	}
}
