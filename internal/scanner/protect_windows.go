//go:build windows

package scanner

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func enforceThreat(path, quarantineDir string) error {
	if err := os.MkdirAll(quarantineDir, 0755); err != nil {
		return err
	}
	// attempt to kill running processes with this executable path
	killCmd := fmt.Sprintf(`$p=%q; Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -eq $p } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }`, path)
	_ = exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", killCmd).Run()

	dst := filepath.Join(quarantineDir, filepath.Base(path)+"."+timestampSuffix())
	mv := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", fmt.Sprintf(`Move-Item -LiteralPath %q -Destination %q -Force`, path, dst))
	if out, err := mv.CombinedOutput(); err != nil {
		return fmt.Errorf("quarantine failed: %v %s", err, string(out))
	}
	return nil
}
