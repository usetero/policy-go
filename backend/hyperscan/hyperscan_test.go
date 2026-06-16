package hyperscan

import "testing"

// Smoke test: the relocated Compile/Scan/Close path still matches correctly,
// including case-insensitivity and the scratch pool across repeated scans.
func TestScan(t *testing.T) {
	m, err := New().Compile([]string{"foo", "ba.", "QUX"}, true)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	defer m.Close()

	for _, tc := range []struct {
		data string
		want [3]bool
	}{
		{"a foo here", [3]bool{true, false, false}},
		{"bar and baz", [3]bool{false, true, false}},
		{"qux lower", [3]bool{false, false, true}}, // caseless
		{"nothing", [3]bool{false, false, false}},
	} {
		matched := make([]bool, 3)
		if err := m.Scan([]byte(tc.data), matched); err != nil {
			t.Fatalf("scan %q: %v", tc.data, err)
		}
		if [3]bool(matched) != tc.want {
			t.Errorf("scan %q = %v, want %v", tc.data, matched, tc.want)
		}
	}
}
