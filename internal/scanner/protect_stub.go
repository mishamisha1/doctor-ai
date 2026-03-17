//go:build !windows

package scanner

func enforceThreat(path, quarantineDir string) error {
	_ = path
	_ = quarantineDir
	return nil
}
