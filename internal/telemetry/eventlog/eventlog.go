package eventlog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type Source struct {
	Log string `json:"log"`
	IDs []int  `json:"ids"`
}

// WinTime умеет парсить:
// 1) RFC3339: "2026-02-07T12:34:56Z"
// 2) PowerShell/.NET формат: "\/Date(1770466382085)\/" (миллисекунды)
type WinTime struct{ time.Time }

func (wt *WinTime) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		wt.Time = time.Time{}
		return nil
	}

	// /Date(1770466382085)/ или \/Date(1770466382085)\/
	if strings.Contains(s, "Date(") {
		// вытащим число из Date(...)
		// оставим только цифры в начале после "Date("
		// примеры: /Date(1770...)/, \/Date(1770...)\/, /Date(1770...+0500)/
		i := strings.Index(s, "Date(")
		if i >= 0 {
			s2 := s[i+len("Date("):]
			// обрежем по ')'
			if j := strings.Index(s2, ")"); j >= 0 {
				s2 = s2[:j]
			}
			// оставим только leading digits (до знака +/-, если есть)
			for k := 0; k < len(s2); k++ {
				if s2[k] < '0' || s2[k] > '9' {
					s2 = s2[:k]
					break
				}
			}
			ms, err := strconv.ParseInt(s2, 10, 64)
			if err != nil {
				return err
			}
			wt.Time = time.Unix(0, ms*int64(time.Millisecond))
			return nil
		}
	}

	// RFC3339
	t, err := time.Parse(time.RFC3339, s)
	if err == nil {
		wt.Time = t
		return nil
	}

	// запасной вариант (иногда PS отдаёт без TZ)
	t2, err2 := time.Parse("2006-01-02T15:04:05", s)
	if err2 == nil {
		wt.Time = t2
		return nil
	}

	return err
}

type Item struct {
	LogName     string  `json:"LogName"`
	Id          int     `json:"Id"`
	Provider    string  `json:"ProviderName"`
	TimeCreated WinTime `json:"TimeCreated"`
	Message     string  `json:"Message"`
}

type Reader struct {
	MaxEvents int
}

func (r *Reader) ReadSince(src Source, since time.Time) ([]Item, error) {
	sinceStr := since.Format(time.RFC3339)

	ids := ""
	for i, id := range src.IDs {
		if i > 0 {
			ids += ","
		}
		ids += fmt.Sprintf("%d", id)
	}

	ps := fmt.Sprintf(`
$ht=@{LogName='%s'; Id=%s; StartTime=[datetime]::Parse('%s')}
Get-WinEvent -FilterHashtable $ht -MaxEvents %d -ErrorAction SilentlyContinue |
Select-Object LogName,Id,ProviderName,TimeCreated,Message |
ConvertTo-Json -Depth 3
`, src.Log, ids, sinceStr, r.MaxEvents)

	cmd := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps)
	out, err := cmd.CombinedOutput()
	outStr := string(out)

	if err != nil {
		// пустой вывод — не шумим (бывает, если нет доступа/нет событий/глюк PS)
		if strings.TrimSpace(outStr) == "" {
			return nil, nil
		}
		// нет событий — это НЕ ошибка
		if strings.Contains(outStr, "NoMatchingEventsFound") ||
			strings.Contains(outStr, "No events were found") {
			return nil, nil
		}
		return nil, fmt.Errorf("Get-WinEvent failed: %w\n%s", err, outStr)
	}

	out = bytes.TrimSpace(out)
	if len(out) == 0 || string(out) == "null" {
		return nil, nil
	}

	if out[0] == '{' {
		var one Item
		if e := json.Unmarshal(out, &one); e != nil {
			return nil, e
		}
		return []Item{one}, nil
	}

	var arr []Item
	if e := json.Unmarshal(out, &arr); e != nil {
		return nil, e
	}
	return arr, nil
}
