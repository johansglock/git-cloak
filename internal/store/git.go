package store

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// gitEnvBlocklist are git environment variables that may be set when git-cloak is
// invoked as a remote helper (pointing at the *local* repo). They must be
// stripped before running git against the encrypted-store mirror, or git would
// operate on the wrong repository.
var gitEnvBlocklist = []string{
	"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE",
	"GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
	"GIT_COMMON_DIR", "GIT_NAMESPACE",
}

// gitRunner runs git commands against a fixed working directory with a scrubbed
// environment and a deterministic identity (so commits leak no author metadata).
type gitRunner struct {
	dir string
}

func scrubbedEnv() []string {
	out := make([]string, 0, len(os.Environ())+6)
	for _, kv := range os.Environ() {
		blocked := false
		for _, b := range gitEnvBlocklist {
			if strings.HasPrefix(kv, b+"=") {
				blocked = true
				break
			}
		}
		if !blocked {
			out = append(out, kv)
		}
	}
	// Deterministic, content-free identity for store commits.
	out = append(out,
		"GIT_AUTHOR_NAME=git-cloak",
		"GIT_AUTHOR_EMAIL=git-cloak@localhost",
		"GIT_COMMITTER_NAME=git-cloak",
		"GIT_COMMITTER_EMAIL=git-cloak@localhost",
		"GIT_TERMINAL_PROMPT=0",
	)
	return out
}

func (g gitRunner) command(args ...string) *exec.Cmd {
	full := append([]string{"-C", g.dir}, args...)
	cmd := exec.Command("git", full...)
	cmd.Env = scrubbedEnv()
	return cmd
}

// run executes git and returns stdout. Errors include git's stderr.
func (g gitRunner) run(args ...string) ([]byte, error) {
	return g.runInput(nil, args...)
}

func (g gitRunner) runInput(stdin []byte, args ...string) ([]byte, error) {
	cmd := g.command(args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	if err != nil {
		return out.Bytes(), &gitError{args: args, stderr: errb.String(), err: err}
	}
	return out.Bytes(), nil
}

type gitError struct {
	args   []string
	stderr string
	err    error
}

func (e *gitError) Error() string {
	return fmt.Sprintf("git %s: %v: %s", strings.Join(e.args, " "), e.err, strings.TrimSpace(e.stderr))
}

func (e *gitError) stderrContains(s string) bool {
	return strings.Contains(e.stderr, s)
}
