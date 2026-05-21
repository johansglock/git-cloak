// Package store manages the encrypted store: a local mirror, under
// .git/cloak/store, of an ordinary private GitHub repo containing only opaque
// encrypted blobs (§6.2, §7). It reads and writes the blob layout, commits, and
// syncs to GitHub by invoking plain git, inheriting the user's existing GitHub
// auth. There is deliberately no backend abstraction: the store is always a git
// repo.
package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Layout constants for files inside the store.
const (
	ConfigFile   = "cloak.json"
	ManifestFile = "manifest.enc"
	PacksDir     = "packs"
	KeysDir      = "keys"
	branch       = "main"
)

// ErrNonFastForward is returned when pushing the store is rejected because
// another writer advanced it first (§8).
var ErrNonFastForward = errors.New("store: push rejected (non-fast-forward); store advanced concurrently")

// Store is a local mirror of the encrypted GitHub repo.
type Store struct {
	dir string
	git gitRunner
}

// OpenOrClone ensures dir is a working clone of the encrypted repo at url. If dir
// does not yet exist it is cloned (an empty remote is fine); otherwise the remote
// URL is refreshed. It does not fetch updates — call Fetch for that.
func OpenOrClone(dir, url string) (*Store, error) {
	s := &Store{dir: dir, git: gitRunner{dir: dir}}
	if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
		// Existing mirror: make sure the remote points where we expect.
		if _, err := s.git.run("remote", "set-url", "origin", url); err != nil {
			// origin may not exist yet
			if _, addErr := s.git.run("remote", "add", "origin", url); addErr != nil {
				return nil, addErr
			}
		}
		return s, nil
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return nil, err
	}
	// Clone via a runner rooted at the parent so `git -C parent clone url base`.
	parent := gitRunner{dir: filepath.Dir(dir)}
	base := filepath.Base(dir)
	if _, err := parent.run("clone", "--origin", "origin", url, base); err != nil {
		return nil, fmt.Errorf("cloning encrypted store: %w", err)
	}
	// Normalize the local branch name to main.
	_, _ = s.git.run("symbolic-ref", "HEAD", "refs/heads/"+branch)
	return s, nil
}

// InitEmpty creates a fresh local mirror with a remote but no clone, for the
// create flow against a pre-created empty GitHub repo.
func InitEmpty(dir, url string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, git: gitRunner{dir: dir}}
	if _, err := s.git.run("init", "-b", branch); err != nil {
		return nil, err
	}
	if _, err := s.git.run("remote", "add", "origin", url); err != nil {
		return nil, err
	}
	return s, nil
}

// Dir returns the mirror's working-tree path.
func (s *Store) Dir() string { return s.dir }

// RemoteHasBranch reports whether origin already has the main branch.
func (s *Store) RemoteHasBranch() bool {
	out, err := s.git.run("ls-remote", "--heads", "origin", branch)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) != ""
}

// HasCommits reports whether the local mirror has any commit on HEAD.
func (s *Store) HasCommits() bool {
	_, err := s.git.run("rev-parse", "--verify", "HEAD")
	return err == nil
}

// Fetch updates the local mirror to match origin/main, discarding any local
// working-tree state. Safe on an empty remote (no-op).
func (s *Store) Fetch() error {
	if !s.RemoteHasBranch() {
		return nil
	}
	if _, err := s.git.run("fetch", "--prune", "origin"); err != nil {
		return err
	}
	// checkout -B repoints the branch to the remote tip and resets tracked files;
	// clean removes any pack/manifest files a prior, un-pushed attempt wrote.
	if _, err := s.git.run("checkout", "-B", branch, "origin/"+branch); err != nil {
		return err
	}
	if _, err := s.git.run("clean", "-fdx"); err != nil {
		return err
	}
	return nil
}

// Commit stages all changes and commits them with a generic message. Returns
// false if there was nothing to commit.
func (s *Store) Commit(msg string) (bool, error) {
	if _, err := s.git.run("add", "-A"); err != nil {
		return false, err
	}
	// Detect staged changes.
	if _, err := s.git.run("diff", "--cached", "--quiet"); err == nil {
		return false, nil // nothing staged
	}
	if _, err := s.git.run("commit", "-q", "-m", msg); err != nil {
		return false, err
	}
	return true, nil
}

// Push pushes the mirror to origin/main. Translates a non-fast-forward rejection
// into ErrNonFastForward. force performs an intentional history rewrite (gc).
func (s *Store) Push(force bool) error {
	args := []string{"push", "--set-upstream", "origin", branch}
	if force {
		args = []string{"push", "--force", "--set-upstream", "origin", branch}
	}
	_, err := s.git.run(args...)
	if err != nil {
		var ge *gitError
		if errors.As(err, &ge) && (ge.stderrContains("non-fast-forward") || ge.stderrContains("[rejected]") || ge.stderrContains("fetch first")) {
			return ErrNonFastForward
		}
		return err
	}
	return nil
}

// --- blob layout I/O -------------------------------------------------------

func (s *Store) path(rel string) string { return filepath.Join(s.dir, filepath.FromSlash(rel)) }

// ReadFile reads a store file by store-relative path.
func (s *Store) ReadFile(rel string) ([]byte, error) { return os.ReadFile(s.path(rel)) }

// WriteFile writes a store file, creating parent directories.
func (s *Store) WriteFile(rel string, data []byte) error {
	p := s.path(rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	return os.WriteFile(p, data, 0o600)
}

// Exists reports whether a store file exists.
func (s *Store) Exists(rel string) bool {
	_, err := os.Stat(s.path(rel))
	return err == nil
}

// Remove deletes a store file (no error if absent).
func (s *Store) Remove(rel string) error {
	err := os.Remove(s.path(rel))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// PackChunkPath returns the store-relative path of a pack chunk file.
func PackChunkPath(packIDHex string, index int) string {
	return fmt.Sprintf("%s/%s.%03d.pack.enc", PacksDir, packIDHex, index)
}

// wrapPath returns the store-relative path of a recipient's wrap file.
func wrapPath(recipientID string) string { return KeysDir + "/" + recipientID + ".wrap" }

// WriteWrap stores a recipient's wrap file.
func (s *Store) WriteWrap(recipientID string, data []byte) error {
	return s.WriteFile(wrapPath(recipientID), data)
}

// ReadWrap reads a recipient's wrap file.
func (s *Store) ReadWrap(recipientID string) ([]byte, error) {
	return s.ReadFile(wrapPath(recipientID))
}

// HasWrap reports whether a recipient's wrap file exists.
func (s *Store) HasWrap(recipientID string) bool {
	return s.Exists(wrapPath(recipientID))
}

// DeleteWrap removes a recipient's wrap file.
func (s *Store) DeleteWrap(recipientID string) error {
	return s.Remove(wrapPath(recipientID))
}

// ListWraps returns the recipient ids that have wrap files, sorted.
func (s *Store) ListWraps() ([]string, error) {
	entries, err := os.ReadDir(s.path(KeysDir))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var ids []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, ".wrap") {
			ids = append(ids, strings.TrimSuffix(name, ".wrap"))
		}
	}
	sort.Strings(ids)
	return ids, nil
}

// RemoveAllPacks deletes every pack chunk file (used by gc before writing the
// consolidated pack).
func (s *Store) RemoveAllPacks() error {
	err := os.RemoveAll(s.path(PacksDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// RewriteHistory collapses the mirror to a single fresh root commit containing
// the current working tree, so a subsequent force-push shrinks the GitHub repo's
// history (used by gc). The caller must Push(force=true) afterwards.
func (s *Store) RewriteHistory(msg string) error {
	if _, err := s.git.run("checkout", "--orphan", "__cloak_gc"); err != nil {
		return err
	}
	if _, err := s.git.run("add", "-A"); err != nil {
		return err
	}
	if _, err := s.git.run("commit", "-q", "-m", msg); err != nil {
		return err
	}
	if _, err := s.git.run("branch", "-M", branch); err != nil {
		return err
	}
	return nil
}

// Size returns the total byte size of tracked store content (packs, manifest,
// wraps, config) — the "total store size" reported by status.
func (s *Store) Size() (int64, error) {
	var total int64
	err := filepath.Walk(s.dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Skip the .git internals so we report logical content size.
		if info.IsDir() && info.Name() == ".git" {
			return filepath.SkipDir
		}
		if !info.IsDir() {
			total += info.Size()
		}
		return nil
	})
	return total, err
}
