package analyzer

import (
	"strings"

	"doctor-ai/internal/model"
)

type Action struct {
	Type   string // kill | quarantine | disable_autorun | firewall_block
	Target string
	Reason string
}

func RecommendActions(inc *model.Incident) []Action {
	// Никакой агрессивной реакции без high
	if inc.Severity != "high" {
		return nil
	}

	actions := []Action{}

	// 1) kill по pid
	for _, e := range inc.Events {
		if e.Type == "process_create" {
			pid := strGet(e.Data, "pid", "Pid", "ProcessId")
			if pid != "" {
				actions = append(actions, Action{
					Type:   "kill",
					Target: pid,
					Reason: "High-risk incident: stop suspicious process",
				})
				break
			}
		}
	}

	// 2) quarantine по path (если есть file_create/процесс из temp)
	for _, e := range inc.Events {
		if e.Type == "file_create" {
			path := strGet(e.Data, "target_file", "TargetFilename", "path")
			if path != "" {
				actions = append(actions, Action{
					Type:   "quarantine",
					Target: path,
					Reason: "High-risk incident: quarantine dropped file",
				})
				break
			}
		}
	}

	// 3) disable autorun (если есть ключ)
	for _, e := range inc.Events {
		if e.Type == "autorun_change" || e.Type == "registry_set" {
			key := strGet(e.Data, "key", "Key")
			name := strGet(e.Data, "name", "Name", "value_name")
			if strings.Contains(strings.ToLower(key), `\currentversion\run`) && name != "" {
				actions = append(actions, Action{
					Type:   "disable_autorun",
					Target: key + " :: " + name,
					Reason: "High-risk incident: remove persistence",
				})
				break
			}
		}
	}

	return actions
}
