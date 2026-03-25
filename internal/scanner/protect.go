package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"doctor-ai/internal/ai"
)

type ProtectConfig struct {
	Roots         []string
	IncidentPaths []string
	MaxFindings   int
	MinScore      int
	EnableAI      bool
	OpenAIKey     string
	AIModel       string
	QuarantineDir string
}

type ProtectAction struct {
	Path    string
	Score   int
	Verdict string
	Action  string
	Note    string
}

type ProtectResult struct {
	Scan    Result
	Actions []ProtectAction
}

func normalizeProtectConfig(cfg ProtectConfig) ProtectConfig {
	if len(cfg.Roots) == 0 {
		cfg.Roots = DefaultRoots()
	}
	if cfg.MaxFindings <= 0 {
		cfg.MaxFindings = 50
	}
	if cfg.MinScore <= 0 {
		cfg.MinScore = 70
	}
	if cfg.QuarantineDir == "" {
		cfg.QuarantineDir = "quarantine"
	}
	if cfg.AIModel == "" {
		cfg.AIModel = "gpt-5-nano"
	}
	return cfg
}

func BuildAutoprotectPlan(ctx context.Context, cfg ProtectConfig) (ProtectResult, error) {
	cfg = normalizeProtectConfig(cfg)
	scanRes, err := ScanQuick(cfg.Roots, cfg.MaxFindings)
	if err != nil {
		return ProtectResult{}, err
	}

	pr := ProtectResult{Scan: scanRes}
	for _, f := range scanRes.Matches {
		if f.Score < cfg.MinScore {
			continue
		}
		verdict := "suspicious"
		note := "heuristic high score"
		if cfg.EnableAI && strings.TrimSpace(cfg.OpenAIKey) != "" {
			v, n := aiVerdict(ctx, cfg.OpenAIKey, cfg.AIModel, f)
			if v != "" {
				verdict, note = v, n
			}
		}
		action := "quarantined+kill"
		if verdict == "allow" {
			action = "skipped"
		}
		pr.Actions = append(pr.Actions, ProtectAction{Path: f.Path, Score: f.Score, Verdict: verdict, Action: action, Note: note})
	}
	for _, p := range uniquePathLike(cfg.IncidentPaths) {
		pr.Actions = append(pr.Actions, ProtectAction{Path: p, Score: cfg.MinScore, Verdict: "incident", Action: "quarantined+kill", Note: "from-correlator"})
	}
	return pr, nil
}

func RunAutoprotect(ctx context.Context, cfg ProtectConfig) (ProtectResult, error) {
	cfg = normalizeProtectConfig(cfg)
	pr, err := BuildAutoprotectPlan(ctx, cfg)
	if err != nil {
		return ProtectResult{}, err
	}
	for i := range pr.Actions {
		a := &pr.Actions[i]
		if a.Action == "skipped" {
			continue
		}
		if err := enforceThreat(a.Path, cfg.QuarantineDir); err != nil {
			a.Action = "failed"
			if a.Verdict == "incident" {
				a.Note = "from-correlator: " + err.Error()
			} else {
				a.Note = err.Error()
			}
		}
	}
	return pr, nil
}

func uniquePathLike(paths []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		k := strings.ToLower(p)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, p)
	}
	return out
}

func aiVerdict(ctx context.Context, key, model string, f Finding) (string, string) {
	c := ai.NewClient(key, model)
	summary := fmt.Sprintf("File: %s\nScore: %d\nReasons: %s\nSize: %d\nTask: Reply one word ONLY: block or allow", f.Path, f.Score, strings.Join(f.Reason, "; "), f.Size)
	txt, err := c.Explain(ctx, summary)
	if err != nil {
		return "", "ai-error"
	}
	if v, ok := parseAIVerdictToken(txt); ok {
		if v == "allow" {
			return "allow", "ai-allow"
		}
		if v == "block" {
			return "block", "ai-block"
		}
	}
	return "suspicious", "ai-unclear"
}

func parseAIVerdictToken(s string) (string, bool) {
	v := strings.ToLower(strings.TrimSpace(s))
	v = strings.Trim(v, "`\"'.,:;!?()[]{}")
	// Принимаем только строгий однословный токен, чтобы ответы вроде
	// "block, do not allow" или "disallow" не интерпретировались неверно.
	switch v {
	case "allow", "block":
		return v, true
	default:
		return "", false
	}
}

func FormatProtectResult(r ProtectResult) string {
	var b strings.Builder
	b.WriteString(FormatResult(r.Scan))
	b.WriteString("\n[Knight Mode] actions:\n")
	if len(r.Actions) == 0 {
		b.WriteString("No auto-actions taken.\n")
		return b.String()
	}
	for i, a := range r.Actions {
		fmt.Fprintf(&b, "%d) %s | score=%d | verdict=%s | action=%s\n   note: %s\n", i+1, a.Path, a.Score, a.Verdict, a.Action, a.Note)
	}
	return b.String()
}

func FormatProtectPreview(r ProtectResult) string {
	var b strings.Builder
	b.WriteString(FormatResult(r.Scan))
	b.WriteString("\n[Knight Mode Preview] planned actions:\n")
	if len(r.Actions) == 0 {
		b.WriteString("No actions planned.\n")
		return b.String()
	}
	for i, a := range r.Actions {
		fmt.Fprintf(&b, "%d) %s | score=%d | verdict=%s | WILL=%s\n   note: %s\n", i+1, a.Path, a.Score, a.Verdict, a.Action, a.Note)
	}
	return b.String()
}

func LoadOpenAIKey(logsDir string) string {
	if v := strings.TrimSpace(os.Getenv("OPENAI_API_KEY")); v != "" {
		return v
	}
	b, err := os.ReadFile(filepath.Join(logsDir, ".openai_key"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func timestampSuffix() string {
	return time.Now().Format("20060102_150405")
}
