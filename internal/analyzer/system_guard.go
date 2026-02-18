package analyzer

import (
	"path/filepath"
	"strings"

	"doctor-ai/internal/model"
)

func IsSystemIncident(inc *model.Incident) bool {
	for _, e := range inc.Events {
		if e.Type != "process_create" {
			continue
		}

		img := strGet(e.Data, "image", "Image")
		imgLower := strings.ToLower(filepath.Clean(img))

		signed := boolGet(e.Data, "signed", "Signed")
		company := strGet(e.Data, "company", "Company")

		// 1) Microsoft signed + standard path => системное
		if signed && strings.EqualFold(company, "Microsoft Corporation") && isStandardPath(img) {
			return true
		}

		// 2) Любой процесс из C:\Windows\... => лучше спросить
		if strings.HasPrefix(imgLower, `c:\windows\`) {
			return true
		}
	}
	return false
}
