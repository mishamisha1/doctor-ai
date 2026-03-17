package registrywatch

// WatchKey is a registry key descriptor (e.g. HKLM\\...\\Run).
type WatchKey struct {
	Hive string `json:"hive"` // HKCU/HKLM
	Path string `json:"path"`
}

type Snapshot map[string]map[string]string

// key = "HKLM\\Software\\...\\Run", values[name]=data

type Change struct {
	Key  string
	Name string
	Old  string
	New  string
	Type string // added/modified/removed
}

func MakeKeyId(w WatchKey) string {
	return w.Hive + `\\` + w.Path
}
