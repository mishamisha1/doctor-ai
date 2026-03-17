package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanQuick_FindsSuspiciousTempScript(t *testing.T) {
	d := t.TempDir()
	tmp := filepath.Join(d, "Temp")
	if err := os.MkdirAll(tmp, 0755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(tmp, "invoice.pdf.js")
	if err := os.WriteFile(p, []byte("WScript.Echo('hi')"), 0644); err != nil {
		t.Fatal(err)
	}

	res, err := ScanQuick([]string{d}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Matches) == 0 {
		t.Fatalf("expected suspicious match, got 0 (scanned=%d)", res.ScannedFiles)
	}
}
