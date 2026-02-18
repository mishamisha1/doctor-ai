package agent

import "strings"

// очень простой wildcard matcher: '*' = любой хвост/вставка
func matchWildcard(s, pattern string) bool {
	s = strings.ToLower(s)
	p := strings.ToLower(pattern)

	parts := strings.Split(p, "*")
	if len(parts) == 1 {
		return s == p
	}

	// начинается ли с первого куска
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]

	// середина
	for i := 1; i < len(parts)-1; i++ {
		idx := strings.Index(s, parts[i])
		if idx < 0 {
			return false
		}
		s = s[idx+len(parts[i]):]
	}

	// заканчивается ли последним куском
	last := parts[len(parts)-1]
	return last == "" || strings.HasSuffix(s, last)
}

func matchAny(s string, patterns []string) bool {
	for _, p := range patterns {
		if p == "" {
			continue
		}
		if matchWildcard(s, p) {
			return true
		}
	}
	return false
}
