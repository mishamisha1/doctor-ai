package collector

import (
	"fmt"
	"os/exec"
)

type PS1Args struct {
	PS1Path     string
	Cmd         string // scan/plan/fix/...
	PolicyPath  string
	Auto        bool
	WorkingDir  string // optional; script uses "." for LogDir etc.
}

func RunDoctorPS1(a PS1Args) error {
	out, err := RunDoctorPS1WithOutput(a)
	if err != nil {
		return err
	}
	_ = out
	return nil
}

// RunDoctorPS1WithOutput runs doctor.ps1 and returns combined stdout+stderr.
func RunDoctorPS1WithOutput(a PS1Args) (string, error) {
	args := []string{
		"-NoProfile",
		"-ExecutionPolicy", "Bypass",
		"-File", a.PS1Path,
		"-cmd", a.Cmd,
		"-PolicyPath", a.PolicyPath,
	}
	if a.Auto {
		args = append(args, "-Auto")
	}

	cmd := exec.Command("powershell.exe", args...)
	if a.WorkingDir != "" {
		cmd.Dir = a.WorkingDir
	}
	out, err := cmd.CombinedOutput()
	outStr := string(out)
	if err != nil {
		return outStr, fmt.Errorf("doctor.ps1 failed: %w\n%s", err, outStr)
	}
	return outStr, nil
}
