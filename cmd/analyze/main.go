package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"doctor-ai/internal/runner"
)

func main() {
	fs := flag.NewFlagSet("analyze", flag.ExitOnError)
	in := fs.String("in", "logs/edr_events.jsonl", "path to edr_events.jsonl")
	logs := fs.String("logs", "logs", "logs dir (for .openai_key and scan_*.json)")
	enableAI := fs.Bool("ai", false, "enable AI explain")
	aiMax := fs.Int("ai-max", 3, "max incidents to explain")
	aiOut := fs.String("ai-out", "", "ai output file")
	aiModel := fs.String("ai-model", "gpt-4o-mini", "model")
	_ = fs.Parse(os.Args[1:])

	// Resolve paths relative to executable dir
	binDir, _ := filepath.Abs(filepath.Dir(os.Args[0]))
	if !filepath.IsAbs(*in) {
		*in = filepath.Join(binDir, *in)
	}
	if !filepath.IsAbs(*logs) {
		*logs = filepath.Join(binDir, *logs)
	}

	opts := runner.AnalyzeOpts{
		InPath:   *in,
		LogsDir:  *logs,
		EnableAI: *enableAI,
		AIMax:    *aiMax,
		AIModel:  *aiModel,
		AIOut:    *aiOut,
	}
	if opts.AIOut != "" && !filepath.IsAbs(opts.AIOut) {
		opts.AIOut = filepath.Join(binDir, opts.AIOut)
	}

	res, err := runner.RunAnalyze(context.Background(), opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}

	fmt.Print(res.Log.String())
	for i, rep := range res.AIReports {
		fmt.Printf("\n========== AI Report %d ==========\n%s\n", i+1, rep)
	}
}
