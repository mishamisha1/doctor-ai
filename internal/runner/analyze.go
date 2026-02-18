package runner

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"doctor-ai/internal/ai"
	"doctor-ai/internal/analyzer"
	"doctor-ai/internal/hashlist"
	"doctor-ai/internal/model"
	"doctor-ai/internal/virustotal"
)

// AnalyzeResult contains analysis output for display.
type AnalyzeResult struct {
	Incidents   []*model.Incident
	ScanSummary string
	AIReports   []string
	Log         strings.Builder
}

func (r *AnalyzeResult) logf(format string, args ...any) {
	fmt.Fprintf(&r.Log, format+"\n", args...)
}

// RunAnalyze reads edr_events.jsonl and latest scan_*.json, runs correlator, optionally calls AI.
func RunAnalyze(ctx context.Context, opts AnalyzeOpts) (*AnalyzeResult, error) {
	res := &AnalyzeResult{}

	// 1) Load events from JSONL
	events, err := loadEventsFromJSONL(opts.InPath)
	if err != nil {
		return nil, fmt.Errorf("load edr_events.jsonl: %w", err)
	}
	res.logf("Загружено %d событий из %s", len(events), opts.InPath)

	// 2) Load latest scan
	var scan *model.Scan
	var scanPath string
	if scanPath, err = model.FindLatestScan(opts.LogsDir); err == nil {
		if scan, err = model.LoadScan(scanPath); err == nil {
			res.logf("Загружен скан: %s (Host: %s, Processes: %d, Autoruns: %d, Net: %d)",
				scanPath, scan.Hostname, len(scan.Processes), len(scan.Autoruns), len(scan.Net))
			res.ScanSummary = ai.BuildScanSummary(scan)
		}
	} else {
		res.logf("Скан не найден (будет использоваться только edr_events): %v", err)
	}

	// 3) Correlate
	corr := analyzer.NewCorrelator(10 * time.Minute)
	var incidents []*model.Incident
	for _, evt := range events {
		if inc := corr.Add(evt); inc != nil {
			incidents = append(incidents, inc)
		}
	}
	res.Incidents = incidents
	res.logf("Обнаружено инцидентов: %d", len(incidents))

	// 4) Output incidents
	for i, inc := range incidents {
		res.logf("--- Incident %d ---", i+1)
		res.logf("  ID: %s | Key: %s | Score: %d | Severity: %s", inc.ID, inc.Key, inc.Score, inc.Severity)
		for _, r := range inc.Reasons {
			res.logf("  - %s", r)
		}
	}

	// 5) Hashlist + VirusTotal + AI explain
	hl, _ := hashlist.New(
		filepath.Join(opts.LogsDir, "whitelist_hashes.json"),
		filepath.Join(opts.LogsDir, "blacklist_hashes.json"),
	)
	vtKey, _ := os.ReadFile(filepath.Join(opts.LogsDir, ".vt_key"))
	vt := virustotal.NewClient(strings.TrimSpace(string(vtKey)))
	openAIKey := os.Getenv("OPENAI_API_KEY")
	if openAIKey == "" {
		if b, err := os.ReadFile(filepath.Join(opts.LogsDir, ".openai_key")); err == nil {
			openAIKey = strings.TrimSpace(string(b))
		}
	}

	if opts.EnableAI && len(incidents) > 0 {
		max := opts.AIMax
		if max <= 0 || max > len(incidents) {
			max = len(incidents)
		}
		for i := 0; i < max && i < len(incidents); i++ {
			inc := incidents[i]
			hashes := extractHashes(inc)

			// Check hashlist first (only if we have hashes)
			if len(hashes) > 0 {
				allWhite, anyBlack := true, false
				for _, h := range hashes {
					if hl.IsBlacklisted(h) {
						anyBlack = true
						break
					}
					if !hl.IsWhitelisted(h) {
						allWhite = false
					}
				}
				if anyBlack {
					res.AIReports = append(res.AIReports, "[Blacklist] Хэш в blacklist. Угроза.")
					res.logf("  Incident %d: blacklist", i+1)
					continue
				}
				if allWhite {
					res.AIReports = append(res.AIReports, "[Whitelist] Хэши проверены, чисто.")
					res.logf("  Incident %d: whitelist (skip AI)", i+1)
					continue
				}
			}

			// VT check for unknown hashes
			vtThreat := false
			for _, h := range hashes {
				if hl.IsWhitelisted(h) || hl.IsBlacklisted(h) {
					continue
				}
				pos, tot, err := vt.CheckHash(ctx, h)
				if err == nil && tot > 0 {
					if pos > 0 {
						_ = hl.AddToBlacklist(h)
						res.AIReports = append(res.AIReports, fmt.Sprintf("[VT] %s: %d/%d — угроза", h[:16]+"...", pos, tot))
						res.logf("  Hash %s: VT %d/%d -> blacklist", h[:16]+"...", pos, tot)
						vtThreat = true
						break
					}
					_ = hl.AddToWhitelist(h)
					res.logf("  Hash %s: VT 0/%d -> whitelist", h[:16]+"...", tot)
				}
			}
			if vtThreat {
				continue
			}

			// AI explain
			if openAIKey != "" {
				summary := ai.BuildIncidentSummary(inc)
				if res.ScanSummary != "" {
					summary = trimStr(res.ScanSummary, 500) + "\n" + summary
				}
				res.logf("AI объяснение для инцидента %d...", i+1)
				txt, err := ai.NewClient(openAIKey, opts.AIModel).Explain(ctx, summary)
				if err != nil {
					res.AIReports = append(res.AIReports, fmt.Sprintf("Ошибка AI: %v", err))
					res.logf("  AI ошибка: %v", err)
					continue
				}
				res.AIReports = append(res.AIReports, txt)
				res.logf("  OK")
			} else {
				res.AIReports = append(res.AIReports, "[Нет OpenAI] Установите ключ в Settings.")
			}
		}
		if openAIKey == "" && len(res.AIReports) == 0 {
			res.logf("OPENAI_API_KEY не задан, AI объяснения пропущены")
		}
	}

	// 6) Write AI reports to file if requested
	if opts.AIOut != "" && len(res.AIReports) > 0 {
		var sb strings.Builder
		for i, rep := range res.AIReports {
			sb.WriteString(fmt.Sprintf("=== Incident %d AI Report ===\n\n%s\n\n", i+1, rep))
		}
		if err := os.WriteFile(opts.AIOut, []byte(sb.String()), 0644); err != nil {
			res.logf("Не удалось записать AI отчёт: %v", err)
		} else {
			res.logf("AI отчёт сохранён в %s", opts.AIOut)
		}
	}

	return res, nil
}

// AnalyzeOpts configures RunAnalyze.
type AnalyzeOpts struct {
	InPath   string // path to edr_events.jsonl
	LogsDir  string // for .openai_key, scan_*.json
	EnableAI bool
	AIMax    int
	AIModel  string
	AIOut    string // optional file to write AI reports
}

// QuickThreatCount returns incident count without AI (fast).
func QuickThreatCount(inPath string) (events int, incidents int, err error) {
	evts, err := loadEventsFromJSONL(inPath)
	if err != nil {
		return 0, 0, err
	}
	corr := analyzer.NewCorrelator(10 * time.Minute)
	var incs int
	for _, evt := range evts {
		if corr.Add(evt) != nil {
			incs++
		}
	}
	return len(evts), incs, nil
}

func extractHashes(inc *model.Incident) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, e := range inc.Events {
		if e.Data == nil {
			continue
		}
		for _, k := range []string{"hash", "sha256", "Sha256", "Hash", "md5", "MD5"} {
			if v, ok := e.Data[k]; ok {
				if s, ok := v.(string); ok && len(s) >= 32 {
					s = strings.TrimSpace(strings.ToLower(s))
					if _, ok := seen[s]; !ok {
						seen[s] = struct{}{}
						out = append(out, s)
					}
					break
				}
			}
		}
	}
	return out
}

func trimStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// ExtractHashesFromFile reads scan_*.json or edr_*.jsonl and returns unique hashes (SHA256/MD5).
func ExtractHashesFromFile(path string) ([]string, error) {
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".jsonl" {
		return extractHashesFromJSONL(path)
	}
	if ext == ".json" {
		return extractHashesFromJSON(path)
	}
	return nil, fmt.Errorf("unsupported file type: %s", ext)
}

func extractHashesFromJSONL(path string) ([]string, error) {
	events, err := loadEventsFromJSONL(path)
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	var out []string
	for _, e := range events {
		if e.Data == nil {
			continue
		}
		for _, k := range []string{"hash", "sha256", "Sha256", "Hash", "md5", "MD5"} {
			if v, ok := e.Data[k]; ok {
				if s, ok := v.(string); ok && len(s) >= 32 {
					s = strings.TrimSpace(strings.ToLower(s))
					if (len(s) == 64 || len(s) == 40) && isHexString(s) {
						if _, ok := seen[s]; !ok {
							seen[s] = struct{}{}
							out = append(out, s)
						}
					}
					break
				}
			}
		}
	}
	return out, nil
}

func extractHashesFromJSON(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	return collectHashesFromValue(raw), nil
}

func collectHashesFromValue(v interface{}) []string {
	seen := map[string]struct{}{}
	var out []string
	var walk func(interface{})
	walk = func(x interface{}) {
		switch t := x.(type) {
		case string:
			s := strings.TrimSpace(strings.ToLower(t))
			if (len(s) == 64 || len(s) == 40) && isHexString(s) {
				if _, ok := seen[s]; !ok {
					seen[s] = struct{}{}
					out = append(out, s)
				}
			}
		case map[string]interface{}:
			for _, val := range t {
				walk(val)
			}
		case []interface{}:
			for _, val := range t {
				walk(val)
			}
		}
	}
	walk(v)
	return out
}

func isHexString(s string) bool {
	for _, c := range s {
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			continue
		}
		return false
	}
	return true
}

func loadEventsFromJSONL(path string) ([]model.Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var events []model.Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var evt model.Event
		if err := json.Unmarshal([]byte(line), &evt); err != nil {
			continue // skip malformed lines
		}
		events = append(events, evt)
	}
	return events, sc.Err()
}
