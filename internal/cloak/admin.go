package cloak

import (
	"errors"
	"fmt"
	"slices"

	"github.com/johans/git-cloak/internal/crypto"
	"github.com/johans/git-cloak/internal/store"
)

// Status summarizes the encrypted store for `git cloak status`.
type Status struct {
	URL            string
	Generation     uint64
	PackCount      int
	ChunkCount     int
	ObjectCount    int
	StoreSizeBytes int64
	RecipientCount int
	DEKGenerations int
	Head           string
	Refs           map[string]string
}

// Status reads the manifest and reports store metadata.
func (s *Session) Status() (*Status, error) {
	m, err := s.ReadManifest()
	if err != nil {
		return nil, err
	}
	size, err := s.Store.Size()
	if err != nil {
		return nil, err
	}
	st := &Status{
		URL:            s.repo.URL,
		Generation:     m.Generation,
		PackCount:      len(m.Packs),
		StoreSizeBytes: size,
		RecipientCount: len(s.Config.Recipients),
		DEKGenerations: len(s.DEKs.Keys),
		Head:           m.Head,
		Refs:           m.Refs,
	}
	for _, p := range m.Packs {
		st.ChunkCount += p.Chunks
		st.ObjectCount += p.ObjectCount
	}
	return st, nil
}

// Verify fetches the store and verifies all AEAD tags and manifest consistency.
// It is read-only and reports the first corruption it finds (§12 `verify`).
func (s *Session) Verify() error {
	m, err := s.ReadManifest()
	if err != nil {
		return fmt.Errorf("manifest: %w", err)
	}
	for _, p := range m.Packs {
		dek, err := s.DEKs.Get(p.DEKGeneration)
		if err != nil {
			return fmt.Errorf("pack %s: %w", p.PackID, err)
		}
		// VerifyPack opens every chunk in order and reports a missing or
		// tampered chunk; no separate existence pre-check is needed.
		if err := s.Store.VerifyPack(p.PackID, p.Chunks, p.DEKGeneration, dek); err != nil {
			return fmt.Errorf("pack %s failed verification: %w", p.PackID, err)
		}
	}
	return nil
}

// mutateStore re-reads the store, applies a mutation, commits, and pushes,
// retrying on a non-fast-forward rejection (§8). apply receives the freshly
// re-read config each attempt and should leave the working tree in the desired
// state.
func (s *Session) mutateStore(apply func(cfg *store.Config) error) error {
	var lastErr error
	for attempt := 0; attempt < maxPushRetries; attempt++ {
		if attempt > 0 {
			if err := s.Store.Fetch(); err != nil {
				return err
			}
		}
		cfg, err := s.Store.ReadConfig()
		if err != nil {
			return err
		}
		s.Config = cfg
		if err := apply(cfg); err != nil {
			return err
		}
		if _, err := s.Store.Commit(commitMsg); err != nil {
			return err
		}
		perr := s.Store.Push(false)
		if perr == nil {
			return nil
		}
		if errors.Is(perr, store.ErrNonFastForward) {
			lastErr = perr
			continue
		}
		return perr
	}
	return fmt.Errorf("store push rejected after %d retries (%v); re-run after `git pull`", maxPushRetries, lastErr)
}

// Recipient describes a wrapped recipient for listing.
type Recipient struct {
	ID        string
	PublicKey string
	IsSelf    bool
	HasWrap   bool
}

// ListRecipients returns the recipients recorded in cloak.json.
func (s *Session) ListRecipients() ([]Recipient, error) {
	out := make([]Recipient, 0, len(s.Config.Recipients))
	for _, tok := range s.Config.Recipients {
		pub, err := crypto.ParsePublicKey(tok)
		if err != nil {
			// Tolerate an unparseable entry rather than failing the whole list.
			out = append(out, Recipient{PublicKey: tok})
			continue
		}
		id := crypto.RecipientID(pub)
		out = append(out, Recipient{
			ID:        id,
			PublicKey: tok,
			IsSelf:    id == s.Identity.ID(),
			HasWrap:   s.Store.HasWrap(id),
		})
	}
	return out, nil
}

// AddRecipient wraps all DEK generations to a new recipient's public key, records
// them in cloak.json, and pushes (§12 `add-recipient`).
func (s *Session) AddRecipient(pub [32]byte) (string, error) {
	id := crypto.RecipientID(pub)
	tok := crypto.PublicKeyString(pub)
	wrap, err := crypto.WrapDEKSet(s.DEKs, pub)
	if err != nil {
		return "", err
	}
	err = s.mutateStore(func(cfg *store.Config) error {
		if err := s.Store.WriteWrap(id, wrap); err != nil {
			return err
		}
		if !slices.Contains(cfg.Recipients, tok) {
			cfg.Recipients = append(cfg.Recipients, tok)
		}
		return s.Store.WriteConfig(cfg)
	})
	return id, err
}

// RemoveRecipient deletes a recipient's wrap file and removes them from
// cloak.json. It does NOT rotate the key — the caller should prompt for that.
func (s *Session) RemoveRecipient(id string) error {
	if id == s.Identity.ID() {
		return errors.New("refusing to remove yourself")
	}
	return s.mutateStore(func(cfg *store.Config) error {
		if err := s.Store.DeleteWrap(id); err != nil {
			return err
		}
		cfg.Recipients = filterRecipients(cfg.Recipients, id)
		return s.Store.WriteConfig(cfg)
	})
}

func filterRecipients(toks []string, removeID string) []string {
	out := toks[:0:0]
	for _, tok := range toks {
		pub, err := crypto.ParsePublicKey(tok)
		if err == nil && crypto.RecipientID(pub) == removeID {
			continue
		}
		out = append(out, tok)
	}
	return out
}
