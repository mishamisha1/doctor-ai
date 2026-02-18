package registrywatch

import (
	"fmt"
	"sort"

	"golang.org/x/sys/windows/registry"
)

type WatchKey struct {
	Hive string `json:"hive"` // HKCU/HKLM
	Path string `json:"path"`
}

type Snapshot map[string]map[string]string

// key = "HKLM\Software\...\Run", values[name]=data

func ReadKey(w WatchKey) (map[string]string, error) {
	var root registry.Key
	switch w.Hive {
	case "HKCU":
		root = registry.CURRENT_USER
	case "HKLM":
		root = registry.LOCAL_MACHINE
	default:
		return nil, fmt.Errorf("unknown hive: %s", w.Hive)
	}

	k, err := registry.OpenKey(root, w.Path, registry.READ)
	if err != nil {
		// ключ может не существовать — это не фатал
		return nil, nil
	}
	defer k.Close()

	names, err := k.ReadValueNames(0)
	if err != nil {
		return nil, err
	}

	out := map[string]string{}
	for _, name := range names {
		s, _, err := k.GetStringValue(name)
		if err == nil {
			out[name] = s
			continue
		}
		// если не строка — пропускаем
	}
	return out, nil
}

func MakeKeyId(w WatchKey) string {
	return w.Hive + `\` + w.Path
}

type Change struct {
	Key  string
	Name string
	Old  string
	New  string
	Type string // added/modified/removed
}

func Diff(prev, cur map[string]string, key string) []Change {
	changes := []Change{}

	for n, newV := range cur {
		oldV, ok := prev[n]
		if !ok {
			changes = append(changes, Change{Key: key, Name: n, Old: "", New: newV, Type: "added"})
		} else if oldV != newV {
			changes = append(changes, Change{Key: key, Name: n, Old: oldV, New: newV, Type: "modified"})
		}
	}
	for n, oldV := range prev {
		if _, ok := cur[n]; !ok {
			changes = append(changes, Change{Key: key, Name: n, Old: oldV, New: "", Type: "removed"})
		}
	}

	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Key == changes[j].Key {
			return changes[i].Name < changes[j].Name
		}
		return changes[i].Key < changes[j].Key
	})
	return changes
}
