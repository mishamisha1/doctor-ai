package registrywatch

import "testing"

func TestDiff_DetectsAddModifyRemoveAndSorts(t *testing.T) {
	prev := map[string]string{"A": "1", "B": "2"}
	cur := map[string]string{"B": "3", "C": "4"}

	changes := Diff(prev, cur, `HKCU\\Software\\Test`)
	if len(changes) != 3 {
		t.Fatalf("expected 3 changes, got %d", len(changes))
	}
	if changes[0].Name != "A" || changes[0].Type != "removed" {
		t.Fatalf("unexpected first change: %+v", changes[0])
	}
	if changes[1].Name != "B" || changes[1].Type != "modified" {
		t.Fatalf("unexpected second change: %+v", changes[1])
	}
	if changes[2].Name != "C" || changes[2].Type != "added" {
		t.Fatalf("unexpected third change: %+v", changes[2])
	}
}
