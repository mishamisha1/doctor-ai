package analyzer

import "doctor-ai/internal/model"

type Decision struct {
	Mode       string // "auto" | "ask" | "none"
	Why        string
	Actions    []Action
	Confidence float64
}

func DecideResponse(inc *model.Incident) Decision {
	acts := RecommendActions(inc)

	// если нет high — ничего не делаем
	if inc.Severity != "high" || len(acts) == 0 {
		return Decision{Mode: "none", Why: "not high severity or no actions", Actions: nil, Confidence: confidenceFromScore(inc.Score)}
	}

	// системное — спросить
	if IsSystemIncident(inc) {
		return Decision{
			Mode:       "ask",
			Why:        "system-related target detected (guard)",
			Actions:    acts,
			Confidence: confidenceFromScore(inc.Score),
		}
	}

	// иначе auto
	return Decision{
		Mode:       "auto",
		Why:        "high severity + non-system target",
		Actions:    acts,
		Confidence: confidenceFromScore(inc.Score),
	}
}

func confidenceFromScore(score int) float64 {
	// простая шкала: 0..100 -> 0..1
	if score <= 0 {
		return 0.0
	}
	if score >= 100 {
		return 1.0
	}
	return float64(score) / 100.0
}
