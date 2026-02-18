package analyzer

import (
	"fmt"
)

func strGet(m map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			switch x := v.(type) {
			case string:
				return x
			case float64:
				return fmt.Sprintf("%.0f", x)
			case int:
				return fmt.Sprintf("%d", x)
			case int64:
				return fmt.Sprintf("%d", x)
			}
		}
	}
	return ""
}
