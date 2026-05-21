package cloak

import (
	"fmt"

	"github.com/johans/git-cloak/internal/crypto"
	"github.com/johans/git-cloak/internal/store"
)

// RotateKey creates a new DEK generation, re-wraps the full DEK set to every
// current recipient, and re-encrypts the manifest under the new current DEK with
// a bumped generation. Packs already in the store keep their old DEK generation
// and stay readable; future packs use the new one. A removed recipient (whose
// wrap is gone) does not receive the new generation, so they cannot read future
// pushes — though they retain whatever they already cloned (N3).
func (s *Session) RotateKey() error {
	newDEKs, err := s.DEKs.Rotate()
	if err != nil {
		return err
	}

	err = s.mutateStore(func(cfg *store.Config) error {
		// Re-wrap to each recipient still listed in cloak.json.
		for _, tok := range cfg.Recipients {
			pub, perr := crypto.ParsePublicKey(tok)
			if perr != nil {
				return fmt.Errorf("recipient %q: %w", tok, perr)
			}
			id := crypto.RecipientID(pub)
			if !s.Store.HasWrap(id) {
				// Recipient was removed; skip (do not re-grant access).
				continue
			}
			wrap, werr := crypto.WrapDEKSet(newDEKs, pub)
			if werr != nil {
				return werr
			}
			if err := s.Store.WriteWrap(id, wrap); err != nil {
				return err
			}
		}
		cfg.DEKGenerations = len(newDEKs.Keys)
		if err := s.Store.WriteConfig(cfg); err != nil {
			return err
		}

		// Re-encrypt the manifest with the new current DEK and bump generation.
		m, rerr := s.ReadManifest()
		if rerr != nil {
			return rerr
		}
		newM := cloneManifest(m)
		newM.Generation = m.Generation + 1
		newKey, kerr := newDEKs.CurrentKey()
		if kerr != nil {
			return kerr
		}
		blob, eerr := newM.EncryptPadded(newKey, newDEKs.Current, cfg.ManifestPadding)
		if eerr != nil {
			return eerr
		}
		if err := s.Store.WriteFile(store.ManifestFile, blob); err != nil {
			return err
		}
		return s.advanceGeneration(newM.Generation)
	})
	if err != nil {
		return err
	}
	// Adopt the new key set for the remainder of this session.
	s.DEKs = newDEKs
	return nil
}
