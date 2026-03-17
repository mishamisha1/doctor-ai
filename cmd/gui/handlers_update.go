package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"doctor-ai/internal/hashlist"
	"doctor-ai/internal/model"
	"doctor-ai/internal/runner"
	"doctor-ai/internal/virustotal"
)

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func handleVTKey(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		key := r.FormValue("key")
		keyPath := filepath.Join(logsDir, ".vt_key")
		if err := os.WriteFile(keyPath, []byte(key), 0600); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Write([]byte("OK"))
		return
	}
	keyPath := filepath.Join(logsDir, ".vt_key")
	if _, err := os.Stat(keyPath); err == nil {
		w.Write([]byte("1"))
	} else {
		w.Write([]byte("0"))
	}
}

func handleHashlist(w http.ResponseWriter, r *http.Request) {
	hl, err := hashlist.New(
		filepath.Join(logsDir, "whitelist_hashes.json"),
		filepath.Join(logsDir, "blacklist_hashes.json"),
	)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"whitelist": []string{}, "blacklist": []string{}})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"whitelist": hl.Whitelist(),
		"blacklist": hl.Blacklist(),
	})
}

func handleVTFileList(w http.ResponseWriter, r *http.Request) {
	scans, _ := model.FindAllScans(logsDir)
	edrGlob, _ := filepath.Glob(filepath.Join(logsDir, "edr_*.jsonl"))
	type fileItem struct {
		Name string `json:"name"`
		Path string `json:"path"`
	}
	scanItems := make([]fileItem, 0, len(scans))
	for _, p := range scans {
		scanItems = append(scanItems, fileItem{Name: filepath.Base(p), Path: p})
	}
	edrItems := make([]fileItem, 0, len(edrGlob))
	for _, p := range edrGlob {
		edrItems = append(edrItems, fileItem{Name: filepath.Base(p), Path: p})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"scans": scanItems,
		"edr":   edrItems,
	})
}

func handleCheckFileVT(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST only", 405)
		return
	}
	filePath := r.FormValue("path")
	if filePath == "" {
		http.Error(w, "missing path", 400)
		return
	}
	// path must be under logsDir or baseDir
	if !strings.HasPrefix(filepath.Clean(filePath), filepath.Clean(logsDir)) &&
		!strings.HasPrefix(filepath.Clean(filePath), filepath.Clean(baseDir)) {
		http.Error(w, "forbidden path", 403)
		return
	}
	hashes, err := runner.ExtractHashesFromFile(filePath)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	hl, err := hashlist.New(
		filepath.Join(logsDir, "whitelist_hashes.json"),
		filepath.Join(logsDir, "blacklist_hashes.json"),
	)
	if err != nil {
		http.Error(w, "hashlist: "+err.Error(), 500)
		return
	}
	vtKey, _ := os.ReadFile(filepath.Join(logsDir, ".vt_key"))
	vt := virustotal.NewClient(strings.TrimSpace(string(vtKey)))
	if vt.APIKey == "" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("Сначала сохраните VirusTotal API ключ в настройках."))
		return
	}

	var logOut strings.Builder
	logOut.WriteString(fmt.Sprintf("Файл: %s\n", filepath.Base(filePath)))
	logOut.WriteString(fmt.Sprintf("Найдено хэшей: %d\n\n", len(hashes)))
	checked, white, black := 0, 0, 0
	for _, h := range hashes {
		if hl.IsWhitelisted(h) {
			logOut.WriteString(fmt.Sprintf("%s... whitelist (пропуск)\n", h[:min(16, len(h))]))
			white++
			continue
		}
		if hl.IsBlacklisted(h) {
			logOut.WriteString(fmt.Sprintf("%s... blacklist (пропуск)\n", h[:min(16, len(h))]))
			black++
			continue
		}
		pos, tot, err := vt.CheckHash(r.Context(), h)
		checked++
		if err != nil {
			logOut.WriteString(fmt.Sprintf("%s... VT ошибка: %v\n", h[:min(16, len(h))], err))
			continue
		}
		if tot == 0 {
			logOut.WriteString(fmt.Sprintf("%s... VT: не найден\n", h[:min(16, len(h))]))
			continue
		}
		if pos > 0 {
			_ = hl.AddToBlacklist(h)
			logOut.WriteString(fmt.Sprintf("%s... VT %d/%d -> blacklist\n", h[:min(16, len(h))], pos, tot))
			black++
		} else {
			_ = hl.AddToWhitelist(h)
			logOut.WriteString(fmt.Sprintf("%s... VT 0/%d -> whitelist\n", h[:min(16, len(h))], tot))
			white++
		}
	}
	logOut.WriteString(fmt.Sprintf("\nИтого: проверено %d, добавлено в whitelist: %d, в blacklist: %d", checked, white, black))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(logOut.String()))
}
