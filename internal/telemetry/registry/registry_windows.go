//go:build windows

package registrywatch

import (
	"fmt"

	"golang.org/x/sys/windows/registry"
)

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
