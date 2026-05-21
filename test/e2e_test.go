// Package e2e runs the end-to-end shell integration test (test/e2e.sh) as part of
// `go test`, so CI exercises the full git-cloak lifecycle against a local bare
// repo standing in for GitHub. The script builds the binaries itself.
package e2e

import (
	"os"
	"os/exec"
	"testing"
)

func TestEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping end-to-end shell test in -short mode")
	}
	for _, bin := range []string{"bash", "git", "go"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not available: %v", bin, err)
		}
	}
	cmd := exec.Command("bash", "e2e.sh")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("e2e.sh failed: %v", err)
	}
}
