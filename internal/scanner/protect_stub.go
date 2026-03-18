//go:build !windows

package scanner

import "fmt"

func enforceThreat(path, quarantineDir string) error {
	return fmt.Errorf("autoprotect enforcement is unsupported on this OS (%s): %s -> %s", runtimeGOOS(), path, quarantineDir)
}

func runtimeGOOS() string {
	return "non-windows"
}
