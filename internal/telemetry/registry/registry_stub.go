//go:build !windows

package registrywatch

import "errors"

var errRegistryNotSupported = errors.New("registry watch is supported only on windows")

func ReadKey(w WatchKey) (map[string]string, error) {
	_ = w
	return map[string]string{}, errRegistryNotSupported
}
