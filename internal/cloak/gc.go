package cloak

import (
	"fmt"

	"github.com/johans/git-cloak/internal/store"
)

// GC consolidates the store: it imports all current objects, repacks everything
// reachable from the manifest refs into one pack encrypted with the current DEK,
// rewrites the store with a fresh single-commit history, force-pushes it, and
// bumps the generation. This is the only operation permitted to be O(total
// history) (§14) and the only one that force-pushes (§8).
func (s *Session) GC() error {
	m, err := s.ReadManifest()
	if err != nil {
		return err
	}
	if len(m.Packs) == 0 {
		return nil // nothing to consolidate
	}

	// Ensure all objects are present locally so we can repack them.
	if _, err := s.FetchAll(); err != nil {
		return err
	}

	dek, err := s.DEKs.CurrentKey()
	if err != nil {
		return err
	}

	newM := cloneManifest(m)
	newM.Generation = m.Generation + 1
	newM.Packs = nil

	if err := s.Store.RemoveAllPacks(); err != nil {
		return err
	}
	rec, err := s.buildPack(dek, s.localRefShas(m), nil)
	if err != nil {
		return err
	}
	if rec != nil {
		newM.Packs = append(newM.Packs, *rec)
	}

	blob, err := s.encryptManifest(newM)
	if err != nil {
		return err
	}
	if err := s.Store.WriteFile(store.ManifestFile, blob); err != nil {
		return err
	}
	if err := s.Store.RewriteHistory(commitMsg); err != nil {
		return err
	}
	if err := s.Store.Push(true); err != nil {
		return fmt.Errorf("force-pushing consolidated store: %w", err)
	}

	// Advance the high-water mark and reset the imported-pack cache to just the
	// consolidated pack (its objects are already present locally).
	state, err := s.repo.LoadState()
	if err != nil {
		return err
	}
	if newM.Generation > state.LastGeneration {
		state.LastGeneration = newM.Generation
	}
	state.ImportedPacks = map[string]bool{}
	for _, p := range newM.Packs {
		state.ImportedPacks[p.PackID] = true
	}
	return s.repo.SaveState(state)
}
