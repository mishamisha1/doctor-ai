package model

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Scan struct {
	Hostname  string `json:"Hostname"`
	Time      string `json:"Time"`
	Processes []any  `json:"Processes"`
	Autoruns  []any  `json:"Autoruns"`
	Net       []any  `json:"Net"`
}

func LoadScan(path string) (*Scan, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b = bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF})
	b = []byte(strings.ReplaceAll(string(b), "\x00", ""))

	var s Scan
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}
func FindLatestScan(logsDir string) (string, error) {
	matches, err := FindAllScans(logsDir)
	if err != nil || len(matches) == 0 {
		return "", errors.New("no scan_*.json found in logs/")
	}
	return matches[len(matches)-1], nil
}

// FindAllScans returns all scan_*.json paths sorted by name (oldest first).
func FindAllScans(logsDir string) ([]string, error) {
	pattern := filepath.Join(logsDir, "scan_*.json")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}
	sort.Strings(matches)
	return matches, nil
}
