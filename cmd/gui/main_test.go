package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveBaseDir_PrefersWorkingTree(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })

	if err := os.WriteFile(filepath.Join(tmp, "go.mod"), []byte("module example.com/test\n"), 0644); err != nil {
		t.Fatal(err)
	}

	got := resolveBaseDir()
	if got != tmp {
		t.Fatalf("resolveBaseDir() = %q, want %q", got, tmp)
	}
}
