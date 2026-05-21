package cloak

import (
	"fmt"

	"github.com/johans/git-cloak/internal/crypto"
	"github.com/johans/git-cloak/internal/keyring"
	"github.com/johans/git-cloak/internal/manifest"
	"github.com/johans/git-cloak/internal/store"
)

// commitMsg is the deliberately generic commit message used for every store
// commit, so GitHub learns nothing from commit text.
const commitMsg = "cloak store update"

// Create initializes the encrypted store in a pre-created, empty GitHub repo:
// generate a DEK, write cloak.json, wrap the DEK to self, write an empty manifest
// at generation 1, commit and push (§12 `git cloak create`). padManifest > 0
// enables opt-in manifest size-obfuscation padding.
func (r *Repo) Create(prompt keyring.Prompter, padManifest int) error {
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
	if st.HasConfig() {
		return fmt.Errorf("encrypted store at %s is already initialized", r.URL)
	}

	deks, err := crypto.NewDEK()
	if err != nil {
		return err
	}
	dek, err := deks.CurrentKey()
	if err != nil {
		return err
	}

	cfg := store.DefaultConfig([]string{crypto.PublicKeyString(id.Public)})
	if padManifest > 0 {
		cfg.ManifestPadding = padManifest
	}
	if err := st.WriteConfig(cfg); err != nil {
		return err
	}

	wrap, err := crypto.WrapDEKSet(deks, id.Public)
	if err != nil {
		return err
	}
	if err := st.WriteWrap(id.ID(), wrap); err != nil {
		return err
	}

	m := manifest.New(1)
	mblob, err := m.EncryptPadded(dek, deks.Current, padManifest)
	if err != nil {
		return err
	}
	if err := st.WriteFile(store.ManifestFile, mblob); err != nil {
		return err
	}

	if _, err := st.Commit(commitMsg); err != nil {
		return err
	}
	if err := st.Push(false); err != nil {
		return fmt.Errorf("pushing initial store: %w", err)
	}

	state, err := r.LoadState()
	if err != nil {
		return err
	}
	state.LastGeneration = 1
	return r.SaveState(state)
}
