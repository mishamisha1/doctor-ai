package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"doctor-ai/internal/collector"
	"doctor-ai/internal/model"
	"doctor-ai/internal/simulate"
)

func usage() {
	fmt.Println("Usage:")
	fmt.Println("  doctor <command> [command flags]")
	fmt.Println("")
	fmt.Println("Commands:")
	fmt.Println("  scan                run scan via doctor.ps1")
	fmt.Println("  latest-scan          print latest scan file path")
	fmt.Println("  plan|fix|rollback    remediation workflow via doctor.ps1")
	fmt.Println("  avscan|update        extra tasks via doctor.ps1")
	fmt.Println("  driver-install       install driver (ps1)")
	fmt.Println("  driver-auto          driver auto actions (ps1)")
	fmt.Println("  agent-run            run agent.exe --config ...")
	fmt.Println("  analyze              run analyze.exe [--ai ...]")
	fmt.Println("  ai-set-key           store OpenAI API key into <logs>/.openai_key")
	fmt.Println("  ai-test              check OpenAI API key (env or <logs>/.openai_key)")
	fmt.Println("  simulate-edr         generate synthetic EDR events for correlation/protection tests")
	fmt.Println("")
	fmt.Println("Examples:")
	fmt.Println(`  doctor scan --logs logs`)
	fmt.Println(`  doctor fix --auto --ps1 configs/doctor.ps1 --policy configs/policy.json`)
	fmt.Println(`  doctor ai-set-key --logs logs`)
	fmt.Println(`  doctor analyze --in logs/edr_events.jsonl --logs logs --ai --ai-out logs/ai_report.txt`)
	fmt.Println(`  doctor agent-run --config configs/agent.json`)
	fmt.Println(`  doctor simulate-edr --out logs/edr_events.jsonl --scenario mixed --count 30`)
	fmt.Println(`  doctor gui                 launch GUI (doctor-gui.exe)`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	command := os.Args[1]
	self, _ := os.Executable()
	binDir := filepath.Dir(self)

	switch command {

	case "latest-scan":
		{
			fs := flag.NewFlagSet("latest-scan", flag.ExitOnError)
			logs := fs.String("logs", "logs", "logs dir")
			_ = fs.Parse(os.Args[2:])

			p, err := model.FindLatestScan(*logs)
			if err != nil {
				fmt.Fprintln(os.Stderr, "ERROR:", err)
				os.Exit(1)
			}
			fmt.Println(p)
			return
		}

	case "plan", "fix", "rollback", "avscan", "update", "driver-install", "driver-auto":
		{
			fs := flag.NewFlagSet(command, flag.ExitOnError)
			ps1 := fs.String("ps1", "configs/doctor.ps1", "path to doctor.ps1")
			policy := fs.String("policy", "configs/policy.json", "path to policy.json")
			auto := fs.Bool("auto", false, "pass -Auto to fix")
			_ = fs.Parse(os.Args[2:])

			err := collector.RunDoctorPS1(collector.PS1Args{
				PS1Path:    *ps1,
				Cmd:        command,
				PolicyPath: *policy,
				Auto:       *auto && command == "fix",
			})
			if err != nil {
				fmt.Fprintln(os.Stderr, "ERROR:", err)
				os.Exit(1)
			}
			fmt.Println("OK")
			return
		}

	case "scan":
		{
			fs := flag.NewFlagSet("scan", flag.ExitOnError)
			ps1 := fs.String("ps1", "configs/doctor.ps1", "path to doctor.ps1")
			policy := fs.String("policy", "configs/policy.json", "path to policy.json")
			logs := fs.String("logs", "logs", "logs dir")
			_ = fs.Parse(os.Args[2:])

			err := collector.RunDoctorPS1(collector.PS1Args{
				PS1Path:    *ps1,
				Cmd:        "scan",
				PolicyPath: *policy,
				Auto:       false,
			})
			if err != nil {
				fmt.Fprintln(os.Stderr, "ERROR:", err)
				os.Exit(1)
			}

			last, err := model.FindLatestScan(*logs)
			if err == nil {
				scan, err := model.LoadScan(last)
				if err == nil {
					fmt.Println("=== SCAN SUMMARY ===")
					fmt.Println("Host:      ", scan.Hostname)
					fmt.Println("Time:      ", scan.Time)
					fmt.Println("Processes: ", len(scan.Processes))
					fmt.Println("Autoruns:  ", len(scan.Autoruns))
					fmt.Println("Net conns: ", len(scan.Net))
					fmt.Println("Saved to:  ", last)
				}
			}
			return
		}

	case "ai-set-key":
		{
			fs := flag.NewFlagSet("ai-set-key", flag.ExitOnError)
			logs := fs.String("logs", "logs", "logs dir")
			_ = fs.Parse(os.Args[2:])

			keyPath := filepath.Join(*logs, ".openai_key")
			fmt.Print("Paste OpenAI API key: ")
			r := bufio.NewReader(os.Stdin)
			key, _ := r.ReadString('\n')
			key = strings.TrimSpace(key)
			if key == "" {
				fmt.Fprintln(os.Stderr, "ERROR: empty key")
				os.Exit(1)
			}
			if err := os.WriteFile(keyPath, []byte(key), 0600); err != nil {
				fmt.Fprintln(os.Stderr, "ERROR:", err)
				os.Exit(1)
			}
			fmt.Println("OK (saved to", keyPath+")")
			return
		}

	case "ai-test":
		{
			fs := flag.NewFlagSet("ai-test", flag.ExitOnError)
			logs := fs.String("logs", "logs", "logs dir")
			_ = fs.Parse(os.Args[2:])

			key := os.Getenv("OPENAI_API_KEY")
			if key == "" {
				keyPath := filepath.Join(*logs, ".openai_key")
				if b, err := os.ReadFile(keyPath); err == nil {
					key = strings.TrimSpace(string(b))
				}
			}
			if key == "" {
				fmt.Fprintln(os.Stderr, "ERROR: no key. set OPENAI_API_KEY or run doctor ai-set-key --logs <dir>")
				os.Exit(1)
			}
			fmt.Println("OK (key loaded)")
			return
		}

	case "analyze":
		{
			// doctor analyze --in logs/edr_events.jsonl --logs logs --ai --ai-max 2 --ai-out logs/ai_report.txt
			afs := flag.NewFlagSet("analyze", flag.ExitOnError)
			in := afs.String("in", "logs/edr_events.jsonl", "path to edr_events.jsonl")
			enableAI := afs.Bool("ai", false, "enable AI explain")
			aiMax := afs.Int("ai-max", 3, "max incidents to explain")
			aiOut := afs.String("ai-out", "", "ai output file")
			aiModel := afs.String("ai-model", "gpt-5-nano", "model")
			logs := afs.String("logs", "logs", "logs dir (for .openai_key)")
			_ = afs.Parse(os.Args[2:])

			// ключ: env или logs/.openai_key
			if *enableAI && os.Getenv("OPENAI_API_KEY") == "" {
				keyPath := filepath.Join(*logs, ".openai_key")
				if b, err := os.ReadFile(keyPath); err == nil {
					_ = os.Setenv("OPENAI_API_KEY", strings.TrimSpace(string(b)))
				}
			}

			args := []string{"--in", *in, "--logs", *logs}
			if *enableAI {
				args = append(args, "--ai", "--ai-max", fmt.Sprintf("%d", *aiMax), "--ai-model", *aiModel)
				if *aiOut != "" {
					args = append(args, "--ai-out", *aiOut)
				}
			}

			cmd := exec.Command(filepath.Join(binDir, "analyze.exe"), args...)
			cmd.Dir = binDir
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				fmt.Fprintln(os.Stderr, "ERROR:", err)
				os.Exit(1)
			}
			return
		}

	case "agent-run":
		{
			afs := flag.NewFlagSet("agent-run", flag.ExitOnError)
			cfg := afs.String("config", "configs/agent.json", "path to agent config")
			_ = afs.Parse(os.Args[2:])

			cmd := exec.Command(filepath.Join(binDir, "agent.exe"), "--config", *cfg)
			cmd.Dir = binDir
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				fmt.Fprintln(os.Stderr, "ERROR:", err)
				os.Exit(1)
			}
			return
		}

	case "simulate-edr":
		{
			fs := flag.NewFlagSet("simulate-edr", flag.ExitOnError)
			outPath := fs.String("out", "logs/edr_events.jsonl", "output jsonl path")
			scenario := fs.String("scenario", "mixed", "benign|malicious|mixed")
			count := fs.Int("count", 20, "number of events")
			_ = fs.Parse(os.Args[2:])
			if *count <= 0 {
				*count = 20
			}
			events := simulate.GenerateEvents(*scenario, *count)
			if err := simulate.WriteJSONL(*outPath, events); err != nil {
				fmt.Fprintln(os.Stderr, "ERROR:", err)
				os.Exit(1)
			}
			fmt.Printf("OK: generated %d events -> %s\n", len(events), *outPath)
			return
		}

	case "gui":
		{
			guiExe := filepath.Join(binDir, "doctor-gui.exe")
			if _, err := os.Stat(guiExe); err != nil {
				fmt.Fprintln(os.Stderr, "ERROR: doctor-gui.exe not found. Build: go build -o doctor-gui.exe ./cmd/gui")
				os.Exit(1)
			}
			cmd := exec.Command(guiExe)
			cmd.Dir = binDir
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				fmt.Fprintln(os.Stderr, "ERROR:", err)
				os.Exit(1)
			}
			return
		}

	default:
		fmt.Fprintln(os.Stderr, "Unknown command:", command)
		usage()
		os.Exit(2)
	}
}
