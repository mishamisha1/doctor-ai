package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestRunAutoprotect_TakesActionOnHighScore(t *testing.T) {
	d := t.TempDir()
	tmp := filepath.Join(d, "tmp")
	if err := os.MkdirAll(tmp, 0755); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(tmp, "invoice.pdf.js")
	if err := os.WriteFile(f, []byte("alert(1)"), 0644); err != nil {
		t.Fatal(err)
	}

	res, err := RunAutoprotect(context.Background(), ProtectConfig{
		Roots:         []string{d},
		MaxFindings:   10,
		MinScore:      40,
		EnableAI:      false,
		QuarantineDir: filepath.Join(d, "q"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Actions) == 0 {
		t.Fatalf("expected at least one action, got 0; matches=%d", len(res.Scan.Matches))
	}
}
