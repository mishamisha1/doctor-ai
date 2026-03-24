package registrywatch

import "sort"

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
