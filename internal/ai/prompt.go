package ai

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"doctor-ai/internal/model"
)

// BuildScanSummary creates a text summary of scan data for AI context.
func BuildScanSummary(scan *model.Scan) string {
	if scan == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("=== SNAPSHOT (scan_*.json) ===\n")
	b.WriteString(fmt.Sprintf("Host: %s | Time: %s\n", scan.Hostname, scan.Time))
	b.WriteString(fmt.Sprintf("Processes: %d | Autoruns: %d | Net conns: %d\n", len(scan.Processes), len(scan.Autoruns), len(scan.Net)))
	// sample processes (first 5) with Path/CommandLine
	if len(scan.Processes) > 0 {
		b.WriteString("\nПримеры процессов (первые 5):\n")
		limit := 5
		if limit > len(scan.Processes) {
			limit = len(scan.Processes)
		}
		for i := 0; i < limit; i++ {
			p, _ := scan.Processes[i].(map[string]interface{})
			if p == nil {
				continue
			}
			name := getStr(p, "Name")
			path := getStr(p, "Path")
			cmd := getStr(p, "CommandLine")
			if path != "" {
				b.WriteString(fmt.Sprintf("  - %s: %s\n", name, path))
			}
			if cmd != "" && len(cmd) < 200 {
				b.WriteString(fmt.Sprintf("    cmd: %s\n", cmd))
			} else if cmd != "" {
				b.WriteString(fmt.Sprintf("    cmd: %s...\n", trimLen(cmd, 120)))
			}
		}
	}
	if len(scan.Autoruns) > 0 {
		b.WriteString("\nАвтозапуск (первые 3):\n")
		limit := 3
		if limit > len(scan.Autoruns) {
			limit = len(scan.Autoruns)
		}
		for i := 0; i < limit; i++ {
			a, _ := scan.Autoruns[i].(map[string]interface{})
			if a == nil {
				continue
			}
			key := getStr(a, "Key")
			name := getStr(a, "Name")
			data := getStr(a, "Data")
			b.WriteString(fmt.Sprintf("  - %s\\%s = %s\n", key, name, trimLen(data, 100)))
		}
	}
	b.WriteString("\n")
	return b.String()
}

func getStr(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func BuildIncidentSummary(inc *model.Incident) string {
	var b strings.Builder

	b.WriteString("INC: id=" + inc.ID + " score=" + fmt.Sprint(inc.Score) + " sev=" + inc.Severity + "\n")
	if len(inc.Reasons) > 0 {
		for _, r := range inc.Reasons {
			b.WriteString("- " + oneLine(trimLen(r, 80)) + "\n")
		}
	}

	// Сводка по событиям: считаем частоты по (source,type,event_id)
	if len(inc.Events) > 0 {
		b.WriteString("EVENTS SUMMARY:\n")
		type key struct {
			Source string
			Type   string
			EID    int
		}
		counts := map[key]int{}
		for _, ev := range inc.Events {
			counts[key{ev.Source, ev.Type, ev.EventID}]++
		}
		// топ-8 групп
		type row struct {
			K key
			N int
		}
		rows := make([]row, 0, len(counts))
		for k, n := range counts {
			rows = append(rows, row{K: k, N: n})
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].N > rows[j].N })
		if len(rows) > 8 {
			rows = rows[:8]
		}
		for _, r := range rows {
			b.WriteString(fmt.Sprintf("- %s/%s eid=%d x%d\n", r.K.Source, r.K.Type, r.K.EID, r.N))
		}
		b.WriteString("\n")

		// Покажем до 10 конкретных событий, но не “всё подряд” — а только то, где можно вытащить полезные поля
		limit := 5
		if limit > len(inc.Events) {
			limit = len(inc.Events)
		}
		for i := 0; i < limit; i++ {
			ev := inc.Events[i]
			b.WriteString(fmt.Sprintf("[%s] %s/%s %s\n", ev.Source, ev.Type, ev.Timestamp.Format("15:04"), trimLen(extractInteresting(ev.Data), 150)))
		}
	}
	b.WriteString("\nОтвет: вердикт, 2-3 причины, 1 рекомендация. Кратко.")
	return b.String()
}

func extractInteresting(m map[string]interface{}) string {
	if len(m) == 0 {
		return "{}"
	}

	out := map[string]interface{}{}

	// 1) важные ключи в твоих логах
	if v, ok := m["provider"]; ok {
		out["provider"] = v
	}

	// message — режем сильно (экономия токенов)
	if v, ok := m["message"]; ok {
		msg := trimLen(normalizeWS(fmt.Sprintf("%v", v)), 300)
		out["msg"] = msg
	}

	// 2) универсальные ключи (на будущее — sysmon/registry)
	keys := []string{
		"image", "process", "process_path", "command_line", "cmdline",
		"parent_image", "parent_process", "parent_command_line",
		"user", "username", "sid",
		"hash", "sha256", "md5",
		"target", "target_path", "file", "file_path",
		"service", "service_name",
		"driver", "driver_path",
		"registry_key", "registry_value", "key", "value",
		"src_ip", "dst_ip", "ip", "domain", "url",
	}

	for _, k := range keys {
		if v, ok := m[k]; ok {
			out[k] = v
		}
	}

	b, err := json.Marshal(out)
	if err != nil {
		return fmt.Sprintf("%v", out)
	}
	s := oneLine(string(b))
	return trimLen(s, 200)
}

func normalizeWS(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	s = strings.TrimSpace(s)
	// схлопнем множественные пробелы
	for strings.Contains(s, "  ") {
		s = strings.ReplaceAll(s, "  ", " ")
	}
	return s
}

func trimLen(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func extractFromMessage(msg string) map[string]string {
	res := map[string]string{}

	// PowerShell 4104: часто есть ScriptBlock GUID и путь к модулю/скрипту
	// В твоём message есть "ScriptBlock:" и "????:" (скорее всего "Path:")
	if i := strings.Index(strings.ToLower(msg), "scriptblock:"); i >= 0 {
		seg := msg[i:]
		res["scriptblock"] = trimLen(seg, 220)
	}

	// вытащим любой путь, похожий на C:\...
	if p := findFirstWindowsPath(msg); p != "" {
		res["path_hint"] = p
	}

	// вытащим первое упоминание .exe (например Code.exe)
	if exe := findFirstExe(msg); exe != "" {
		res["exe_hint"] = exe
	}

	return res
}

func findFirstWindowsPath(s string) string {
	// очень простой поиск "C:\"
	low := strings.ToLower(s)
	i := strings.Index(low, "c:\\")
	if i < 0 {
		return ""
	}
	// режем до пробела/кавычки
	end := i
	for end < len(s) && end-i < 200 {
		ch := s[end]
		if ch == ' ' || ch == '"' || ch == '\'' || ch == ')' || ch == ',' {
			break
		}
		end++
	}
	return s[i:end]
}

func findFirstExe(s string) string {
	low := strings.ToLower(s)
	i := strings.Index(low, ".exe")
	if i < 0 {
		return ""
	}
	// пробуем взять слово вокруг
	start := i
	for start > 0 && (isWordChar(s[start-1])) && (i-start) < 80 {
		start--
	}
	end := i + 4
	for end < len(s) && isWordChar(s[end]) && (end-start) < 90 {
		end++
	}
	return s[start:end]
}

func isWordChar(b byte) bool {
	if b >= 'a' && b <= 'z' {
		return true
	}
	if b >= 'A' && b <= 'Z' {
		return true
	}
	if b >= '0' && b <= '9' {
		return true
	}
	switch b {
	case '.', '_', '-', '\\', ':':
		return true
	default:
		return false
	}
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.TrimSpace(s)
	if len(s) > 260 {
		return s[:260] + "..."
	}
	return s
}
