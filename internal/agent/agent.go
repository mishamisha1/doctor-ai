package agent

import (
	"fmt"
	"os"
	"time"

	"doctor-ai/internal/collector"
	"doctor-ai/internal/model"
	"doctor-ai/internal/telemetry/eventlog"
	registrywatch "doctor-ai/internal/telemetry/registry"
)

type Agent struct {
	cfg    *Config
	writer *Writer
	state  *State

	regSnap registrywatch.Snapshot
}

func New(cfg *Config, w *Writer, st *State) *Agent {
	return &Agent{
		cfg:     cfg,
		writer:  w,
		state:   st,
		regSnap: registrywatch.Snapshot{},
	}
}

func (a *Agent) Run() error {
	a.writer.Write(model.Event{
		Timestamp: time.Now(),
		Host:      host(),
		Source:    "agent",
		EventID:   0,
		Type:      "start",
		Severity:  "info",
		Data: map[string]interface{}{
			"message": "EDR agent started",
		},
	})

	// Sysmon auto-install (если включено в конфиге)
	if a.cfg.Sysmon.Enabled && a.cfg.Sysmon.AutoInstall {
		err := EnsureSysmon(a.cfg.Sysmon.ExePath, a.cfg.Sysmon.ConfigPath)
		if err != nil {
			a.writer.Write(model.Event{
				Timestamp: time.Now(),
				Host:      host(),
				Source:    "sysmon",
				EventID:   0,
				Type:      "ensure_failed",
				Severity:  "alert",
				Data: map[string]interface{}{
					"message": err.Error(),
				},
			})
		} else {
			a.writer.Write(model.Event{
				Timestamp: time.Now(),
				Host:      host(),
				Source:    "sysmon",
				EventID:   0,
				Type:      "ensure_ok",
				Severity:  "info",
				Data: map[string]interface{}{
					"message": "Sysmon installed/updated",
				},
			})
		}
	}

	// тикеры
	hb := time.NewTicker(time.Duration(a.cfg.IntervalSeconds) * time.Second)
	defer hb.Stop()

	evEvery := time.NewTicker(time.Duration(max(1, a.cfg.EventLog.PollSeconds)) * time.Second)
	defer evEvery.Stop()

	regEvery := time.NewTicker(time.Duration(max(1, a.cfg.Registry.PollSeconds)) * time.Second)
	defer regEvery.Stop()

	evr := &eventlog.Reader{MaxEvents: max(1, a.cfg.EventLog.MaxEventsPerPoll)}

	for {
		select {
		case <-hb.C:
			a.writer.Write(model.Event{
				Timestamp: time.Now(),
				Host:      host(),
				Source:    "agent",
				EventID:   0,
				Type:      "heartbeat",
				Severity:  "info",
				Data: map[string]interface{}{
					"message": "agent alive",
				},
			})

		case <-evEvery.C:
			if a.cfg.EventLog.Enabled {
				a.pollEventLog(evr)
				_ = a.state.Save(a.cfg.State.Path)
			}

		case <-regEvery.C:
			if a.cfg.Registry.Enabled {
				a.pollRegistry()
			}
		}
	}
}

func (a *Agent) pollEventLog(r *eventlog.Reader) {
	for _, s := range a.cfg.EventLog.Sources {
		src := eventlog.Source{Log: s.Log, IDs: s.IDs}

		since := a.state.GetLast(s.Log)
		if since.IsZero() {
			// чтобы не быть пустыми на старте
			since = time.Now().Add(-30 * time.Second)
		}

		items, err := r.ReadSince(src, since)
		if err != nil {
			a.writer.Write(model.Event{
				Timestamp: time.Now(),
				Host:      host(),
				Source:    "eventlog",
				EventID:   0,
				Type:      "read_failed",
				Severity:  "error",
				Data: map[string]interface{}{
					"message": err.Error(),
					"log":     s.Log,
				},
			})
			continue
		}

		for _, it := range items {
			// сохраняем курсор
			a.state.SetLast(s.Log, it.TimeCreated.Time)

			// collector уже возвращает model.Event — просто пишем
			evt := collector.FromEventLogItem(it)

			// на всякий случай проставим Host, если вдруг пусто
			if evt.Host == "" {
				evt.Host = host()
			}

			a.writer.Write(evt)
		}
	}
}

func (a *Agent) pollRegistry() {
	for _, w := range a.cfg.Registry.Watch {
		k := registrywatch.WatchKey{Hive: w.Hive, Path: w.Path}
		keyID := registrywatch.MakeKeyId(k)

		cur, err := registrywatch.ReadKey(k)
		if err != nil {
			a.writer.Write(model.Event{
				Timestamp: time.Now(),
				Host:      host(),
				Source:    "registry",
				EventID:   0,
				Type:      "read_failed",
				Severity:  "error",
				Data: map[string]interface{}{
					"message": err.Error(),
					"key":     keyID,
				},
			})
			continue
		}
		if cur == nil {
			cur = map[string]string{}
		}

		prev := a.regSnap[keyID]
		if prev == nil {
			a.regSnap[keyID] = cur
			continue
		}

		changes := registrywatch.Diff(prev, cur, keyID)
		if len(changes) == 0 {
			continue
		}

		for _, c := range changes {
			sev := "info"
			if c.Type == "added" || c.Type == "modified" {
				sev = "alert"
			}

			data := map[string]interface{}{
				"message": fmt.Sprintf("%s: %s %s", c.Key, c.Type, c.Name),
				"key":     c.Key,
				"name":    c.Name,
				"change":  c.Type,
				"old":     c.Old,
				"new":     c.New,
			}

			a.writer.Write(model.Event{
				Timestamp: time.Now(),
				Host:      host(),
				Source:    "registry",
				EventID:   0,
				Type:      "autorun_change",
				Severity:  sev,
				Data:      data,
			})
		}

		// обновляем снапшот
		a.regSnap[keyID] = cur
	}
}

func host() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	return h
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
