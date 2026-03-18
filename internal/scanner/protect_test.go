package scanner

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
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
	if runtime.GOOS != "windows" {
		failed := 0
		for _, a := range res.Actions {
			if a.Action == "failed" {
				failed++
			}
		}
		if failed == 0 {
			t.Fatalf("expected failed actions on non-windows enforcement stub, got actions=%+v", res.Actions)
		}
	}
}

func TestParseAIVerdictToken_Strict(t *testing.T) {
	tests := []struct {
		in   string
		ok   bool
		want string
	}{
		{in: "allow", ok: true, want: "allow"},
		{in: "BLOCK", ok: true, want: "block"},
		{in: "\"allow\"", ok: true, want: "allow"},
		{in: "block, do not allow", ok: false, want: ""},
		{in: "disallow", ok: false, want: ""},
	}
	for _, tc := range tests {
		got, ok := parseAIVerdictToken(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Fatalf("parseAIVerdictToken(%q) = (%q,%v), want (%q,%v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}
