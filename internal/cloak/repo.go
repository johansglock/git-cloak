// Package cloak is the orchestration layer shared by the porcelain CLI
// (git-cloak) and the remote helper (git-remote-cloak). It ties together the
// crypto, store, manifest, and keyring packages: locating the local repo and the
// encrypted store, unwrapping the repo DEK, and implementing the push, fetch,
// create, verify, rotation, and gc flows with rollback protection.
package cloak

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Repo binds a local git repository to its encrypted GitHub store URL.
type Repo struct {
	GitDir   string // absolute path to the local repo's .git
	URL      string // the GitHub git URL (the part after cloak::)
	storeDir string // GitDir/cloak/store
	stateDir string // GitDir/cloak
	git      localGit
}

// Open binds a Repo from an already-known git dir and store URL.
func Open(gitDir, url string) *Repo {
	gitDir, _ = filepath.Abs(gitDir)
	return &Repo{
		GitDir:   gitDir,
		URL:      url,
		storeDir: filepath.Join(gitDir, "cloak", "store"),
		stateDir: filepath.Join(gitDir, "cloak"),
		git:      localGit{gitDir: gitDir},
	}
}

// DiscoverGitDir resolves the local repo's git dir, honoring GIT_DIR (set when
// running as a remote helper) and falling back to git rev-parse.
func DiscoverGitDir() (string, error) {
	if d := os.Getenv("GIT_DIR"); d != "" {
		return filepath.Abs(d)
	}
	out, err := exec.Command("git", "rev-parse", "--absolute-git-dir").Output()
	if err != nil {
		return "", fmt.Errorf("not inside a git repository: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// DiscoverURL finds the first git remote whose URL begins with cloak:: and
// returns the underlying GitHub URL (with the cloak:: prefix stripped).
func DiscoverURL(gitDir string) (string, error) {
	g := localGit{gitDir: gitDir}
	out, err := g.run("config", "--get-regexp", `^remote\..*\.url$`)
	if err != nil {
		return "", fmt.Errorf("no cloak:: remote configured (add one with `git remote add origin cloak::<github-url>`)")
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		fields := strings.SplitN(sc.Text(), " ", 2)
		if len(fields) != 2 {
			continue
		}
		if strings.HasPrefix(fields[1], "cloak::") {
			return strings.TrimPrefix(fields[1], "cloak::"), nil
		}
	}
	return "", fmt.Errorf("no cloak:: remote configured (add one with `git remote add origin cloak::<github-url>`)")
}

// StripScheme removes a leading cloak:: from a URL if present.
func StripScheme(url string) string { return strings.TrimPrefix(url, "cloak::") }

// localGit runs git plumbing against the local repository. Unlike the store
// runner it deliberately keeps GIT_DIR pointed at the local repo.
type localGit struct {
	gitDir string
}

func (g localGit) command(args ...string) *exec.Cmd {
	cmd := exec.Command("git", args...)
	cmd.Env = append(os.Environ(), "GIT_DIR="+g.gitDir, "GIT_TERMINAL_PROMPT=0")
	return cmd
}

func (g localGit) run(args ...string) ([]byte, error) {
	cmd := g.command(args...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return out.Bytes(), fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}

// revParse resolves a ref or object expression to a 40-hex object id.
func (g localGit) revParse(ref string) (string, error) {
	out, err := g.run("rev-parse", "--verify", ref+"^{}")
	if err != nil {
		// Fall back without peeling (e.g. for a raw sha).
		out, err = g.run("rev-parse", "--verify", ref)
		if err != nil {
			return "", err
		}
	}
	return strings.TrimSpace(string(out)), nil
}

// hasObject reports whether an object exists in the local repo.
func (g localGit) hasObject(sha string) bool {
	_, err := g.run("cat-file", "-e", sha)
	return err == nil
}

// indexPack feeds a decrypted packfile (read from r) into the local object store.
func (g localGit) indexPack(r io.Reader) error {
	cmd := g.command("index-pack", "--stdin", "--fix-thin")
	cmd.Stdin = r
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git index-pack: %v: %s", err, strings.TrimSpace(errb.String()))
	}
	return nil
}
