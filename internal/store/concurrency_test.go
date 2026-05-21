package store

import (
	"errors"
	"path/filepath"
	"testing"
)

// TestTwoWriterNonFastForward exercises the §8 consistency mechanism: when a
// second writer's push is rejected non-fast-forward, it re-fetches, re-applies
// its change onto the new tip, and converges.
func TestTwoWriterNonFastForward(t *testing.T) {
	remote := bareRemote(t)

	// Seed the store so both writers start from a common tip.
	seed := mustClone(t, remote, "seed")
	if err := seed.WriteFile("cloak.json", []byte("{}")); err != nil {
		t.Fatal(err)
	}
	mustCommitPush(t, seed)

	a := mustClone(t, remote, "a")
	b := mustClone(t, remote, "b")
	if err := a.Fetch(); err != nil {
		t.Fatal(err)
	}
	if err := b.Fetch(); err != nil {
		t.Fatal(err)
	}

	// Writer A pushes first.
	if err := a.WriteFile("packs/aaa.000.pack.enc", []byte("A")); err != nil {
		t.Fatal(err)
	}
	mustCommitPush(t, a)

	// Writer B, still on the old tip, tries to push and is rejected.
	if err := b.WriteFile("packs/bbb.000.pack.enc", []byte("B")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Commit("cloak store update"); err != nil {
		t.Fatal(err)
	}
	err := b.Push(false)
	if !errors.Is(err, ErrNonFastForward) {
		t.Fatalf("expected ErrNonFastForward, got %v", err)
	}

	// B re-syncs (gets A's pack), re-applies its own change, and retries.
	if err := b.Fetch(); err != nil {
		t.Fatal(err)
	}
	if !b.Exists("packs/aaa.000.pack.enc") {
		t.Fatal("after fetch, B should see A's pack")
	}
	if err := b.WriteFile("packs/bbb.000.pack.enc", []byte("B")); err != nil {
		t.Fatal(err)
	}
	mustCommitPush(t, b)

	// A final fresh clone has both writers' packs: convergence.
	final := mustClone(t, remote, "final")
	if err := final.Fetch(); err != nil {
		t.Fatal(err)
	}
	if !final.Exists("packs/aaa.000.pack.enc") || !final.Exists("packs/bbb.000.pack.enc") {
		t.Fatal("store did not converge: missing one writer's pack")
	}
}

func mustClone(t *testing.T, remote, name string) *Store {
	t.Helper()
	s, err := OpenOrClone(filepath.Join(t.TempDir(), name), remote)
	if err != nil {
		t.Fatalf("clone %s: %v", name, err)
	}
	return s
}

func mustCommitPush(t *testing.T, s *Store) {
	t.Helper()
	if _, err := s.Commit("cloak store update"); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if err := s.Push(false); err != nil {
		t.Fatalf("push: %v", err)
	}
}
