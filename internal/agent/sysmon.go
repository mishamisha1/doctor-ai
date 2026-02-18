package agent

import (
	"fmt"
	"os"
	"os/exec"
)

func EnsureSysmon(exePath, cfgPath string) error {
	if exePath == "" || cfgPath == "" {
		return fmt.Errorf("sysmon paths are empty")
	}
	if _, err := os.Stat(exePath); err != nil {
		return fmt.Errorf("sysmon exe not found: %s", exePath)
	}
	if _, err := os.Stat(cfgPath); err != nil {
		return fmt.Errorf("sysmon config not found: %s", cfgPath)
	}

	// Проверка установлен ли Sysmon: если сервис есть — обновим конфиг, иначе установим.
	installed := isSysmonServicePresent()

	if installed {
		// Update config
		cmd := exec.Command(exePath, "-c", cfgPath)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("sysmon config update failed: %w\n%s", err, string(out))
		}
		return nil
	}

	// Install (requires admin)
	cmd := exec.Command(exePath, "-accepteula", "-i", cfgPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("sysmon install failed: %w\n%s", err, string(out))
	}
	return nil
}

func isSysmonServicePresent() bool {
	// sc query Sysmon64 / Sysmon
	for _, name := range []string{"Sysmon64", "Sysmon"} {
		cmd := exec.Command("sc.exe", "query", name)
		if err := cmd.Run(); err == nil {
			return true
		}
	}
	return false
}
