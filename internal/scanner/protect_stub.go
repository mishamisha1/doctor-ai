//go:build !windows

package scanner

import (
	"fmt"
	"runtime"
)

func enforceThreat(path, quarantineDir string) error {
	return fmt.Errorf("autoprotect enforcement is unsupported on this OS (%s): %s -> %s", runtimeGOOS(), path, quarantineDir)
}

func runtimeGOOS() string {
	return runtime.GOOS
}
