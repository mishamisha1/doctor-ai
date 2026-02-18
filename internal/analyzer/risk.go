package analyzer

import (
	"path/filepath"
	"strings"

	"doctor-ai/internal/model"
)

type RiskResult struct {
	Score    int
	Severity string // low|medium|high
	Reasons  []string
}

func CalculateRisk(inc *model.Incident) RiskResult {
	score := 0
	reasons := []string{}

	// флаги
	var hasPSBypass bool
	var hasEncoded bool
	var hasTempUnsigned bool
	var hasPersistence bool
	var hasNet bool
	var msSignedStandard bool

	for _, e := range inc.Events {
		switch e.Type {
		case "process_create":
			img := strings.ToLower(strGet(e.Data, "image", "Image"))
			cl := strings.ToLower(strGet(e.Data, "command_line", "CommandLine"))

			if strings.Contains(img, "powershell") || strings.Contains(img, "pwsh") {
				// Bypass / ExecutionPolicy
				if strings.Contains(cl, "bypass") || strings.Contains(cl, "executionpolicy") {
					hasPSBypass = true
				}
				// EncodedCommand
				if strings.Contains(cl, "-enc") || strings.Contains(cl, "encodedcommand") {
					hasEncoded = true
				}
			}

			// Microsoft signed + standard path => снижаем уверенность
			signed := boolGet(e.Data, "signed", "Signed")
			company := strGet(e.Data, "company", "Company")
			if signed && strings.EqualFold(company, "Microsoft Corporation") && isStandardPath(img) {
				msSignedStandard = true
			}

			// unsigned from temp/appdata
			if isUserTempPath(img) && !signed {
				hasTempUnsigned = true
			}

		case "file_create":
			path := strings.ToLower(strGet(e.Data, "target_file", "TargetFilename", "path"))
			// создали в temp/appdata
			if isUserTempPath(path) {
				// если есть hash / signed info — можно усиливать потом
				score += 15
				reasons = append(reasons, "File created in Temp/AppData")
			}

		case "autorun_change", "registry_set":
			key := strings.ToLower(strGet(e.Data, "key", "Key"))
			if strings.Contains(key, `\software\microsoft\windows\currentversion\run`) ||
				strings.Contains(key, `\software\microsoft\windows\currentversion\runonce`) {
				hasPersistence = true
			}

		case "network_connect":
			hasNet = true
		}
	}

	// баллы по признакам (ядро)
	if hasPSBypass {
		score += 30
		reasons = append(reasons, "PowerShell execution with policy bypass")
	}
	if hasEncoded {
		score += 20
		reasons = append(reasons, "PowerShell EncodedCommand detected")
	}
	if hasTempUnsigned {
		score += 20
		reasons = append(reasons, "Unsigned binary executed from Temp/AppData")
	}
	if hasPersistence {
		score += 25
		reasons = append(reasons, "Persistence via Run/RunOnce")
	}
	if hasNet {
		score += 20
		reasons = append(reasons, "Network connection observed in chain")
	}

	// снижающие факторы
	if msSignedStandard {
		score -= 30
		reasons = append(reasons, "Microsoft-signed binary from standard path (confidence reduction)")
	}
	if score < 0 {
		score = 0
	}

	sev := "low"
	if score >= 70 {
		sev = "high"
	} else if score >= 40 {
		sev = "medium"
	}

	return RiskResult{Score: score, Severity: sev, Reasons: unique(reasons)}
}

func isUserTempPath(p string) bool {
	if p == "" {
		return false
	}
	pp := strings.ToLower(filepath.Clean(p))
	return strings.Contains(pp, `\temp\`) ||
		strings.Contains(pp, `\appdata\local\temp\`) ||
		strings.Contains(pp, `\appdata\roaming\`)
}

func unique(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
