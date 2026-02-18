package remediation

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"doctor-ai/internal/analyzer"
	"doctor-ai/internal/model"
)

type Executor struct {
	QuarantineDir string // например "quarantine"
}

func (ex *Executor) Apply(inc *model.Incident, dec analyzer.Decision) error {
	if dec.Mode == "none" || len(dec.Actions) == 0 {
		return nil
	}

	fmt.Printf("\n[RESPONSE] mode=%s confidence=%.2f why=%s\n", dec.Mode, dec.Confidence, dec.Why)
	fmt.Printf("[RESPONSE] recommended actions:\n")
	for _, a := range dec.Actions {
		fmt.Printf("  * %s -> %s (%s)\n", a.Type, a.Target, a.Reason)
	}

	// ask-mode: подтверждение
	if dec.Mode == "ask" {
		if !confirm("System-related incident detected. Apply actions? (y/N): ") {
			fmt.Println("[RESPONSE] skipped by user")
			return nil
		}
	}

	// auto-mode: сразу применяем
	for _, a := range dec.Actions {
		if err := ex.applyOne(a); err != nil {
			fmt.Printf("[RESPONSE] action failed: %s -> %s : %v\n", a.Type, a.Target, err)
		} else {
			fmt.Printf("[RESPONSE] action ok: %s -> %s\n", a.Type, a.Target)
		}
	}
	return nil
}

func (ex *Executor) applyOne(a analyzer.Action) error {
	switch a.Type {
	case "kill":
		// target = pid
		ps := fmt.Sprintf(`Stop-Process -Id %s -Force -ErrorAction Stop`, safePS(a.Target))
		return runPS(ps)

	case "quarantine":
		// target = filepath
		qdir := ex.QuarantineDir
		if qdir == "" {
			qdir = "quarantine"
		}
		_ = os.MkdirAll(qdir, 0755)

		src := a.Target
		dst := filepath.Join(qdir, filepath.Base(src))

		// Move-Item безопаснее чем удаление
		ps := fmt.Sprintf(`Move-Item -LiteralPath %s -Destination %s -Force -ErrorAction Stop`, quotePS(src), quotePS(dst))
		return runPS(ps)

	case "disable_autorun":
		// target format: "HKCU\...\Run :: valueName"
		parts := strings.Split(a.Target, " :: ")
		if len(parts) != 2 {
			return fmt.Errorf("bad target format for disable_autorun")
		}
		key := parts[0]
		name := parts[1]

		// Remove-ItemProperty
		ps := fmt.Sprintf(`Remove-ItemProperty -Path %s -Name %s -ErrorAction Stop`, quotePS(key), quotePS(name))
		return runPS(ps)

	default:
		return fmt.Errorf("unknown action type: %s", a.Type)
	}
}

func runPS(script string) error {
	// Windows PowerShell
	cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, string(out))
	}
	return nil
}

func confirm(prompt string) bool {
	fmt.Print(prompt)
	r := bufio.NewReader(os.Stdin)
	s, _ := r.ReadString('\n')
	s = strings.TrimSpace(strings.ToLower(s))
	return s == "y" || s == "yes"
}

func quotePS(s string) string {
	// одинарные кавычки в PS: экранируем через ''
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func safePS(s string) string {
	// для PID: уберём всё кроме цифр
	out := make([]rune, 0, len(s))
	for _, ch := range s {
		if ch >= '0' && ch <= '9' {
			out = append(out, ch)
		}
	}
	return string(out)
}
