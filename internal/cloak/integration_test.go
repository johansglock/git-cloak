package cloak

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/johans/git-cloak/internal/keyring"
)

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@e",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@e")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// TestCloakAPIEndToEnd drives the orchestration layer directly (no helper
// subprocess) so the push/fetch pipe goroutines run under -race.
func TestCloakAPIEndToEnd(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	home := t.TempDir()
	t.Setenv("GIT_CLOAK_HOME", home)
	if _, err := keyring.GenerateAndSave(keyring.BackendPlaintext, keyring.EnvOrTerminal); err != nil {
		t.Fatal(err)
	}

	// Bare repo standing in for GitHub.
	bare := t.TempDir()
	git(t, ".", "init", "--bare", "-b", "main", bare)
	url := "file://" + bare

	// Source repo with one commit.
	src := t.TempDir()
	git(t, src, "init", "-b", "main")
	if err := os.WriteFile(filepath.Join(src, "f.txt"), []byte("plaintext payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, src, "add", "-A")
	git(t, src, "commit", "-q", "-m", "c1")
	head := git(t, src, "rev-parse", "HEAD")

	repo := Open(filepath.Join(src, ".git"), url)
	if err := repo.Create(keyring.EnvOrTerminal, 0); err != nil {
		t.Fatalf("create: %v", err)
	}
	sess, err := repo.OpenSession(keyring.EnvOrTerminal)
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	if err := sess.Push([]RefUpdate{{Src: "refs/heads/main", Dst: "refs/heads/main"}}); err != nil {
		t.Fatalf("push: %v", err)
	}

	// Fresh repo, fetch via the API, assert the object arrived.
	dst := t.TempDir()
	git(t, dst, "init", "-b", "main")
	repoD := Open(filepath.Join(dst, ".git"), url)
	sessD, err := repoD.OpenSession(keyring.EnvOrTerminal)
	if err != nil {
		t.Fatalf("dst session: %v", err)
	}
	m, err := sessD.FetchAll()
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if m.Refs["refs/heads/main"] != head {
		t.Fatalf("fetched ref mismatch: %q != %q", m.Refs["refs/heads/main"], head)
	}
	if out, err := exec.Command("git", "-C", filepath.Join(dst, ".git"), "cat-file", "-e", head).CombinedOutput(); err != nil {
		t.Fatalf("fetched object missing: %v: %s", err, out)
	}

	// Plaintext must not be present anywhere in the bare store's blobs.
	scan := t.TempDir()
	git(t, ".", "clone", "-q", bare, filepath.Join(scan, "s"))
	if grepRecursive(filepath.Join(scan, "s"), "plaintext payload") {
		t.Fatal("plaintext leaked into the encrypted store")
	}

	// Rollback detection: roll the bare repo back to its first commit and assert
	// the next manifest read on dst (which saw a higher generation) aborts.
	root := git(t, bare, "rev-list", "--max-parents=0", "main")
	git(t, bare, "update-ref", "refs/heads/main", strings.Fields(root)[0])
	sessD2, err := repoD.OpenSession(keyring.EnvOrTerminal)
	if err != nil {
		t.Fatalf("dst session 2: %v", err)
	}
	if _, err := sessD2.ReadManifest(); err == nil {
		t.Fatal("expected rollback to be detected")
	} else if !strings.Contains(strings.ToLower(err.Error()), "rollback") {
		t.Fatalf("expected rollback error, got: %v", err)
	}
}

func grepRecursive(dir, needle string) bool {
	found := false
	filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if strings.Contains(p, "/.git/") {
			return nil
		}
		data, _ := os.ReadFile(p)
		if strings.Contains(string(data), needle) {
			found = true
		}
		return nil
	})
	return found
}
