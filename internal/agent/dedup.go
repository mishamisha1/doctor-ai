package agent

import (
	"fmt"
	"strings"
	"time"

	"doctor-ai/internal/model"
)

type Deduper struct {
	ttl time.Duration
	m   map[string]time.Time
}

func NewDeduper(ttl time.Duration) *Deduper {
	return &Deduper{
		ttl: ttl,
		m:   make(map[string]time.Time, 1024),
	}
}

// Seen возвращает true, если ключ уже был в окне TTL
func (d *Deduper) Seen(key string, now time.Time) bool {
	// очистка "по случаю"
	d.gc(now)

	if t, ok := d.m[key]; ok {
		if now.Sub(t) <= d.ttl {
			return true
		}
	}
	d.m[key] = now
	return false
}

func (d *Deduper) gc(now time.Time) {
	// лёгкая очистка: удаляем старое
	for k, t := range d.m {
		if now.Sub(t) > d.ttl {
			delete(d.m, k)
		}
	}
}

func DedupKey(evt model.Event) string {
	// round(ts, 1s)
	ts := evt.Timestamp.UTC().Truncate(time.Second).Format(time.RFC3339)

	// process_guid / ProcessGuid / processGuid
	pg := strGetAny(evt.Data,
		"process_guid", "ProcessGuid", "processGuid",
		"ProcessGUID", "processGUID",
	)

	// если есть PID, тоже можно добавить
	pid := strGetAny(evt.Data, "pid", "Pid", "ProcessId", "process_id")

	parts := []string{
		evt.Source,
		fmt.Sprintf("%d", evt.EventID),
		ts,
	}
	if pg != "" {
		parts = append(parts, strings.ToLower(pg))
	} else if pid != "" {
		parts = append(parts, "pid="+pid)
	}
	return strings.Join(parts, "|")
}

func strGetAny(m map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			switch x := v.(type) {
			case string:
				return x
			case fmt.Stringer:
				return x.String()
			case float64:
				// json.Unmarshal числа -> float64
				return fmt.Sprintf("%.0f", x)
			case int:
				return fmt.Sprintf("%d", x)
			case int64:
				return fmt.Sprintf("%d", x)
			}
		}
	}
	return ""
}
