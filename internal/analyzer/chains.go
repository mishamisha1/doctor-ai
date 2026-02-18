package analyzer

import (
	"strings"

	"doctor-ai/internal/model"
)

func matchChain(events []model.Event) (bool, []string, []string) {
	// признаки
	var hasPS bool
	var hasTempFile bool
	var hasAutorun bool
	var hasNet bool

	for _, e := range events {
		switch e.Type {
		case "process_create":
			img := strings.ToLower(strGet(e.Data, "image", "Image"))
			cl := strings.ToLower(strGet(e.Data, "command_line", "CommandLine"))
			if strings.Contains(img, "powershell") || strings.Contains(img, "pwsh") {
				hasPS = true
				if strings.Contains(cl, "bypass") || strings.Contains(cl, "-enc") || strings.Contains(cl, "encodedcommand") {
					// усиливаем — но пока считаем как PS
				}
			}

		case "file_create":
			path := strings.ToLower(strGet(e.Data, "target_file", "TargetFilename", "path"))
			if strings.Contains(path, `\temp\`) || strings.Contains(path, `\appdata\local\temp\`) {
				hasTempFile = true
			}

		case "autorun_change", "registry_set":
			key := strings.ToLower(strGet(e.Data, "key", "Key"))
			if strings.Contains(key, `\software\microsoft\windows\currentversion\run`) ||
				strings.Contains(key, `\software\microsoft\windows\currentversion\runonce`) {
				hasAutorun = true
			}

		case "network_connect":
			hasNet = true
		}
	}

	// MVP-логика: 3 из 4 = инцидент
	count := 0
	if hasPS {
		count++
	}
	if hasTempFile {
		count++
	}
	if hasAutorun {
		count++
	}
	if hasNet {
		count++
	}

	if count >= 3 {
		tech := []string{"T1059.001"} // PowerShell
		reasons := []string{}
		if hasPS {
			reasons = append(reasons, "PowerShell process execution")
		}
		if hasTempFile {
			reasons = append(reasons, "File created in Temp/AppData")
		}
		if hasAutorun {
			reasons = append(reasons, "Persistence via Run/RunOnce")
			tech = append(tech, "T1547.001")
		}
		if hasNet {
			reasons = append(reasons, "Network connection after execution")
			tech = append(tech, "T1071")
		}
		return true, tech, reasons
	}

	return false, nil, nil
}
