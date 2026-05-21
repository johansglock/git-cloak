package cloak

import (
	"fmt"
	"slices"

	"github.com/johans/git-cloak/internal/crypto"
	"github.com/johans/git-cloak/internal/keyring"
	"github.com/johans/git-cloak/internal/store"
)

// ExportKey returns the repo DEK set sealed under a passphrase, for out-of-band
// transport to another machine (§12 export-key). The file never contains an
// unprotected key.
func (s *Session) ExportKey(passphrase []byte) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("a non-empty passphrase is required to protect the exported key")
	}
	return crypto.SealPassphrase(s.DEKs.Marshal(), passphrase)
}

// ImportKey ingests a passphrase-sealed DEK set exported elsewhere and grants the
// local identity access by wrapping the DEK set to it and recording it as a
// recipient in the store. This bootstraps a new machine without needing an
// online recipient to add it.
func (r *Repo) ImportKey(blob, passphrase []byte, prompt keyring.Prompter) error {
	plain, err := crypto.OpenPassphrase(blob, passphrase)
	if err != nil {
		return err
	}
	deks, err := crypto.ParseDEKSet(plain)
	if err != nil {
		return fmt.Errorf("imported file is not a valid repo key: %w", err)
	}
	id, err := keyring.Load(prompt)
	if err != nil {
		return err
	}
	st, err := store.OpenOrClone(r.storeDir, r.URL)
	if err != nil {
		return err
	}
	if err := st.Fetch(); err != nil {
		return err
	}
	if !st.HasConfig() {
		return fmt.Errorf("encrypted store at %s is not initialized", r.URL)
	}

	// Build a session-like context to reuse mutateStore.
	cfg, err := st.ReadConfig()
	if err != nil {
		return err
	}
	s := &Session{repo: r, Store: st, Config: cfg, Identity: id, DEKs: deks}
	wrap, err := crypto.WrapDEKSet(deks, id.Public)
	if err != nil {
		return err
	}
	tok := crypto.PublicKeyString(id.Public)
	return s.mutateStore(func(cfg *store.Config) error {
		if err := st.WriteWrap(id.ID(), wrap); err != nil {
			return err
		}
		if !slices.Contains(cfg.Recipients, tok) {
			cfg.Recipients = append(cfg.Recipients, tok)
		}
		return st.WriteConfig(cfg)
	})
}
