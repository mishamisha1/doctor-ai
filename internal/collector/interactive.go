package collector

import (
	"fmt"
	"os/exec"
	"runtime"
)

// StartDoctorPS1InteractiveTerminal launches doctor.ps1 in a separate terminal window.
// Useful for commands that require user input and should not block GUI server terminal.
func StartDoctorPS1InteractiveTerminal(a PS1Args) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("interactive terminal launch is supported on windows only")
	}

	cmdLine := fmt.Sprintf("Set-Location -LiteralPath '%s'; & '%s' -cmd '%s' -PolicyPath '%s'", a.WorkingDir, a.PS1Path, a.Cmd, a.PolicyPath)
	if a.Auto {
		cmdLine += " -Auto"
	}

	c := exec.Command(
		"cmd.exe", "/C", "start", "Doctor AI Interactive",
		"powershell.exe", "-NoExit", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmdLine,
	)
	if a.WorkingDir != "" {
		c.Dir = a.WorkingDir
	}
	if err := c.Start(); err != nil {
		return err
	}
	return nil
}
