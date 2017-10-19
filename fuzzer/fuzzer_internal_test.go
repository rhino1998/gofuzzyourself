package fuzzer

import "testing"

func TestStdinsEmpty(t *testing.T) {
	cmds, err := makeCommandGroup([]string{}, []string{}, []string{})

	if err != nil {
		t.Fatal(err)
	}

	for _, stdin := range cmds.stdins() {
		t.Fatalf("Should not have stdins on empty command: %q", stdin)
	}
}
