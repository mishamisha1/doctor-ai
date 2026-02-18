package analyzer

import (
	"crypto/sha1"
	"encoding/hex"
	"sort"
	"time"

	"doctor-ai/internal/model"
)

type Correlator struct {
	window time.Duration
	buf    map[string][]model.Event
}

func NewCorrelator(window time.Duration) *Correlator {
	return &Correlator{
		window: window,
		buf:    make(map[string][]model.Event, 1024),
	}
}

func (c *Correlator) Add(evt model.Event) *model.Incident {
	key := CorrelationKey(evt)
	if key == "" {
		return nil
	}

	// добавляем
	c.buf[key] = append(c.buf[key], evt)

	// чистим по времени
	c.trim(key, evt.Timestamp)

	// если цепочка совпала — собираем incident и очищаем буфер по ключу
	if ok, techniques, reasons := matchChain(c.buf[key]); ok {
		events := c.buf[key]
		sort.Slice(events, func(i, j int) bool {
			return events[i].Timestamp.Before(events[j].Timestamp)
		})

		start := events[0].Timestamp
		end := events[len(events)-1].Timestamp

		id := incidentID(key, start, end, reasons)

		inc := &model.Incident{
			ID:         id,
			Key:        key,
			Start:      start,
			End:        end,
			Techniques: techniques,
			Reasons:    reasons,
			Events:     events,
		}

		rr := CalculateRisk(inc)
		inc.Score = rr.Score
		inc.Severity = rr.Severity
		// reasons расширяем/перезаписываем (можно объединить)
		inc.Reasons = rr.Reasons

		// очищаем, чтобы не дублировать инцидент
		delete(c.buf, key)

		return inc
	}

	return nil
}

func (c *Correlator) trim(key string, now time.Time) {
	events := c.buf[key]
	if len(events) == 0 {
		return
	}
	cut := now.Add(-c.window)
	out := events[:0]
	for _, e := range events {
		if e.Timestamp.After(cut) {
			out = append(out, e)
		}
	}
	c.buf[key] = out
}

func incidentID(key string, start, end time.Time, reasons []string) string {
	h := sha1.New()
	h.Write([]byte(key))
	h.Write([]byte(start.UTC().Format(time.RFC3339Nano)))
	h.Write([]byte(end.UTC().Format(time.RFC3339Nano)))
	for _, r := range reasons {
		h.Write([]byte(r))
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
}
