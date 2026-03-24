package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type Finding struct {
	Path    string
	Reason  []string
	Score   int
	Size    int64
	ModTime time.Time
	SHA256  string
}

type Result struct {
	ScannedFiles int
	Matches      []Finding
	StartedAt    time.Time
	FinishedAt   time.Time
}

var suspiciousExt = map[string]struct{}{
	".exe": {}, ".dll": {}, ".scr": {}, ".msi": {}, ".bat": {}, ".cmd": {},
	".ps1": {}, ".js": {}, ".vbs": {}, ".hta": {},
}

var doubleExt = regexp.MustCompile(`(?i)\.(pdf|doc|docx|xls|xlsx|txt|jpg|png|zip)\.(exe|scr|bat|cmd|js|vbs|ps1)$`)

func DefaultRoots() []string {
	var roots []string
	if v := strings.TrimSpace(os.Getenv("TEMP")); v != "" {
		roots = append(roots, v)
	}
	if up := strings.TrimSpace(os.Getenv("USERPROFILE")); up != "" {
		roots = append(roots,
			filepath.Join(up, "Downloads"),
			filepath.Join(up, "AppData", "Local", "Temp"),
			filepath.Join(up, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
		)
	}
	return uniqExistingDirs(roots)
}

func ScanQuick(roots []string, maxFindings int) (Result, error) {
	res := Result{StartedAt: time.Now()}
	if maxFindings <= 0 {
		maxFindings = 50
	}
	for _, root := range roots {
		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				return nil
			}
			res.ScannedFiles++
			f, ok := scoreFile(path)
			if !ok {
				return nil
			}
			if len(res.Matches) < maxFindings {
				res.Matches = append(res.Matches, f)
			} else {
				// keep top-N by score
				sort.Slice(res.Matches, func(i, j int) bool { return res.Matches[i].Score > res.Matches[j].Score })
				if f.Score > res.Matches[len(res.Matches)-1].Score {
					res.Matches[len(res.Matches)-1] = f
				}
			}
			return nil
		})
	}
	sort.Slice(res.Matches, func(i, j int) bool {
		if res.Matches[i].Score == res.Matches[j].Score {
			return res.Matches[i].ModTime.After(res.Matches[j].ModTime)
		}
		return res.Matches[i].Score > res.Matches[j].Score
	})
	res.FinishedAt = time.Now()
	return res, nil
}

func scoreFile(path string) (Finding, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return Finding{}, false
	}
	ext := strings.ToLower(filepath.Ext(path))
	if _, ok := suspiciousExt[ext]; !ok {
		return Finding{}, false
	}

	norm := strings.ToLower(filepath.Clean(path))
	score := 0
	reasons := make([]string, 0, 6)

	if strings.Contains(norm, `\temp\`) || strings.Contains(norm, `/tmp/`) {
		score += 40
		reasons = append(reasons, "exec/script in Temp")
	}
	if strings.Contains(norm, `\startup\`) {
		score += 35
		reasons = append(reasons, "located in Startup path")
	}
	if doubleExt.MatchString(norm) {
		score += 25
		reasons = append(reasons, "double-extension masquerading")
	}
	base := strings.ToLower(filepath.Base(norm))
	if strings.HasPrefix(base, ".") {
		score += 10
		reasons = append(reasons, "hidden-like filename")
	}
	if time.Since(fi.ModTime()) <= 72*time.Hour {
		score += 15
		reasons = append(reasons, "recently created/modified")
	}
	if fi.Size() < 6*1024 && (ext == ".js" || ext == ".vbs" || ext == ".ps1" || ext == ".bat" || ext == ".cmd") {
		score += 10
		reasons = append(reasons, "small launcher-like script")
	}
	if score < 40 {
		return Finding{}, false
	}

	sha := ""
	if score >= 70 {
		sha = fileSHA256(path)
	}
	return Finding{Path: path, Reason: reasons, Score: score, Size: fi.Size(), ModTime: fi.ModTime(), SHA256: sha}, true
}

func fileSHA256(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func uniqExistingDirs(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, p := range in {
		if p == "" {
			continue
		}
		cp := filepath.Clean(p)
		if _, ok := seen[cp]; ok {
			continue
		}
		fi, err := os.Stat(cp)
		if err != nil || !fi.IsDir() {
			continue
		}
		seen[cp] = struct{}{}
		out = append(out, cp)
	}
	return out
}

func FormatResult(r Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[Smart Scan] scanned files: %d\n", r.ScannedFiles)
	fmt.Fprintf(&b, "[Smart Scan] suspicious findings: %d\n", len(r.Matches))
	fmt.Fprintf(&b, "[Smart Scan] duration: %s\n\n", r.FinishedAt.Sub(r.StartedAt).Truncate(time.Millisecond))
	if len(r.Matches) == 0 {
		b.WriteString("No high-signal suspicious files found by local heuristics.\n")
		return b.String()
	}
	for i, m := range r.Matches {
		fmt.Fprintf(&b, "%d) score=%d | %s\n", i+1, m.Score, m.Path)
		fmt.Fprintf(&b, "   size=%d bytes | modified=%s\n", m.Size, m.ModTime.Format(time.RFC3339))
		fmt.Fprintf(&b, "   reasons: %s\n", strings.Join(m.Reason, "; "))
		if m.SHA256 != "" {
			fmt.Fprintf(&b, "   sha256: %s\n", m.SHA256)
		}
	}
	return b.String()
}
