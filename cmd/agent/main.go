package main

import (
	"fmt"
	"os"

	"doctor-ai/internal/agent"
)

func main() {
	cfg, err := agent.LoadConfig("configs/agent.json")
	if err != nil {
		fmt.Fprintln(os.Stderr, "config error:", err)
		os.Exit(1)
	}

	w, err := agent.NewWriter(cfg.Output.Path, cfg.Output.RetentionHours, cfg.Output.MaxLines)
	if err != nil {
		fmt.Fprintln(os.Stderr, "writer error:", err)
		os.Exit(1)
	}

	st, err := agent.LoadState(cfg.State.Path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "state error:", err)
		os.Exit(1)
	}

	a := agent.New(cfg, w, st)

	fmt.Println("[EDR] agent running (Ctrl+C to stop)")
	if err := a.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "agent error:", err)
	}
}
