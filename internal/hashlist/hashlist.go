package hashlist

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Store manages whitelist and blacklist of hashes (SHA256).
type Store struct {
	mu         sync.RWMutex
	whitelist  map[string]struct{}
	blacklist  map[string]struct{}
	whitePath  string
	blackPath  string
}

// New creates a Store. whitePath and blackPath are JSON files.
func New(whitePath, blackPath string) (*Store, error) {
	s := &Store{
		whitelist: make(map[string]struct{}),
		blacklist: make(map[string]struct{}),
		whitePath: whitePath,
		blackPath: blackPath,
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if b, err := os.ReadFile(s.whitePath); err == nil {
		var list []string
		_ = json.Unmarshal(b, &list)
		for _, h := range list {
			h = normalizeHash(h)
			if h != "" {
				s.whitelist[h] = struct{}{}
			}
		}
	}
	if b, err := os.ReadFile(s.blackPath); err == nil {
		var list []string
		_ = json.Unmarshal(b, &list)
		for _, h := range list {
			h = normalizeHash(h)
			if h != "" {
				s.blacklist[h] = struct{}{}
			}
		}
	}
	return nil
}

func normalizeHash(h string) string {
	h = strings.TrimSpace(strings.ToLower(h))
	if len(h) == 64 && isHex(h) {
		return h
	}
	if len(h) == 40 && isHex(h) {
		return h
	}
	return ""
}

func isHex(s string) bool {
	for _, c := range s {
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			continue
		}
		return false
	}
	return true
}

func (s *Store) saveWhite() error {
	s.mu.RLock()
	list := make([]string, 0, len(s.whitelist))
	for h := range s.whitelist {
		list = append(list, h)
	}
	s.mu.RUnlock()

	_ = os.MkdirAll(filepath.Dir(s.whitePath), 0755)
	b, _ := json.MarshalIndent(list, "", "  ")
	return os.WriteFile(s.whitePath, b, 0644)
}

func (s *Store) saveBlack() error {
	s.mu.RLock()
	list := make([]string, 0, len(s.blacklist))
	for h := range s.blacklist {
		list = append(list, h)
	}
	s.mu.RUnlock()

	_ = os.MkdirAll(filepath.Dir(s.blackPath), 0755)
	b, _ := json.MarshalIndent(list, "", "  ")
	return os.WriteFile(s.blackPath, b, 0644)
}

// IsWhitelisted returns true if hash was previously checked and clean.
func (s *Store) IsWhitelisted(hash string) bool {
	h := normalizeHash(hash)
	if h == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.whitelist[h]
	return ok
}

// IsBlacklisted returns true if hash is known threat.
func (s *Store) IsBlacklisted(hash string) bool {
	h := normalizeHash(hash)
	if h == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.blacklist[h]
	return ok
}

// AddToWhitelist adds hash and persists.
func (s *Store) AddToWhitelist(hash string) error {
	h := normalizeHash(hash)
	if h == "" {
		return nil
	}
	s.mu.Lock()
	s.whitelist[h] = struct{}{}
	s.mu.Unlock()
	return s.saveWhite()
}

// AddToBlacklist adds hash and persists.
func (s *Store) AddToBlacklist(hash string) error {
	h := normalizeHash(hash)
	if h == "" {
		return nil
	}
	s.mu.Lock()
	s.blacklist[h] = struct{}{}
	s.mu.Unlock()
	return s.saveBlack()
}

// Whitelist returns copy of whitelist.
func (s *Store) Whitelist() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.whitelist))
	for h := range s.whitelist {
		out = append(out, h)
	}
	return out
}

// Blacklist returns copy of blacklist.
func (s *Store) Blacklist() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.blacklist))
	for h := range s.blacklist {
		out = append(out, h)
	}
	return out
}
