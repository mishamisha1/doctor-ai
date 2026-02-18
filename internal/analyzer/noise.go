package analyzer

import (
	"path/filepath"
	"strings"

	"doctor-ai/internal/model"
)

func IsNoise(evt model.Event) bool {
	// 1) __PSScriptPolicyTest_*.ps1
	if containsAny(strGet(evt.Data, "script", "ScriptBlockText", "script_block"), "__PSScriptPolicyTest_") {
		return true
	}
	if containsAny(strGet(evt.Data, "file", "TargetFilename", "target_file", "path"), "__PSScriptPolicyTest_") {
		return true
	}

	// 2) Sysmon EID=7 ImageLoaded: signed Microsoft + стандартный путь => шум
	if evt.Source == "sysmon" && evt.EventID == 7 {
		signed := boolGet(evt.Data, "signed", "Signed")
		company := strGet(evt.Data, "company", "Company")
		img := strGet(evt.Data, "image_loaded", "ImageLoaded", "ImageLoadedPath")

		if signed && strings.EqualFold(company, "Microsoft Corporation") && isStandardPath(img) {
			return true
		}
	}

	// 3) BAM registry шум (если ловишь)
	if evt.Source == "registry" {
		key := strings.ToLower(strGet(evt.Data, "key", "Key", "registry_key"))
		if strings.Contains(key, `\bam\state\usersettings`) {
			return true
		}
	}

	return false
}

func isStandardPath(p string) bool {
	if p == "" {
		return false
	}
	pp := strings.ToLower(filepath.Clean(p))

	if strings.Contains(pp, `\windows\system32\`) || strings.Contains(pp, `\windows\syswow64\`) {
		return true
	}
	if strings.Contains(pp, `\program files\`) || strings.Contains(pp, `\program files (x86)\`) {
		return true
	}
	return false
}

func boolGet(m map[string]interface{}, keys ...string) bool {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			switch x := v.(type) {
			case bool:
				return x
			case string:
				return strings.EqualFold(x, "true")
			}
		}
	}
	return false
}

func containsAny(s string, subs ...string) bool {
	if s == "" {
		return false
	}
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
