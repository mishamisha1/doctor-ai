package main

import "testing"

func TestResolveBaseDir_PrefersWorkingTree(t *testing.T) {
	exists := func(path string) bool {
		return path == "/repo/go.mod"
	}
	got := resolveBaseDirFrom("/repo", "/tmp/go-build/app", exists)
	if got != "/repo" {
		t.Fatalf("resolveBaseDirFrom() = %q, want %q", got, "/repo")
	}
}

func TestResolveBaseDir_PrefersExecutableDirWhenItHasRuntimeLayout(t *testing.T) {
	exists := func(path string) bool {
		return path == "/app/configs"
	}
	got := resolveBaseDirFrom("/repo", "/app", exists)
	if got != "/app" {
		t.Fatalf("resolveBaseDirFrom() = %q, want %q", got, "/app")
	}
}
