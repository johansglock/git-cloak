package cloak

import (
	"errors"
	"fmt"

	"github.com/johans/git-cloak/internal/crypto"
	"github.com/johans/git-cloak/internal/keyring"
	"github.com/johans/git-cloak/internal/manifest"
	"github.com/johans/git-cloak/internal/store"
)

// Session is an unlocked working context against the encrypted store: the local
// identity, the unwrapped repo DEK set, the store mirror, and cloak.json.
type Session struct {
	repo     *Repo
	Store    *store.Store
	Config   *store.Config
	Identity crypto.Identity
	DEKs     crypto.DEKSet
}

// ErrNotRecipient indicates the local identity has no wrap file in the store.
var ErrNotRecipient = errors.New("this identity is not a recipient of the repo key")

// OpenSession loads the identity, syncs the store mirror from GitHub, reads
// cloak.json, and unwraps the repo DEK set. It does not read the manifest.
func (r *Repo) OpenSession(prompt keyring.Prompter) (*Session, error) {
	id, err := keyring.Load(prompt)
	if err != nil {
		return nil, err
	}
	st, err := store.OpenOrClone(r.storeDir, r.URL)
	if err != nil {
		return nil, err
	}
	if err := st.Fetch(); err != nil {
		return nil, err
	}
	if !st.HasConfig() {
		return nil, fmt.Errorf("encrypted store at %s is not initialized (run `git cloak create`)", r.URL)
	}
	cfg, err := st.ReadConfig()
	if err != nil {
		return nil, err
	}
	if !st.HasWrap(id.ID()) {
		return nil, fmt.Errorf("%w\nyour id: %s\nask a repo owner to run: git cloak add-recipient %s",
			ErrNotRecipient, id.ID(), crypto.PublicKeyString(id.Public))
	}
	wrap, err := st.ReadWrap(id.ID())
	if err != nil {
		return nil, err
	}
	deks, err := crypto.UnwrapDEKSet(wrap, id)
	if err != nil {
		return nil, err
	}
	return &Session{repo: r, Store: st, Config: cfg, Identity: id, DEKs: deks}, nil
}

// lookupDEK maps a DEK generation to its key, for manifest/pack decryption.
func (s *Session) lookupDEK(gen uint32) ([]byte, error) { return s.DEKs.Get(gen) }

// encryptManifest seals a manifest with the current DEK, honoring the store's
// optional size-obfuscation padding setting.
func (s *Session) encryptManifest(m *manifest.Manifest) ([]byte, error) {
	dek, err := s.DEKs.CurrentKey()
	if err != nil {
		return nil, err
	}
	pad := 0
	if s.Config != nil {
		pad = s.Config.ManifestPadding
	}
	return m.EncryptPadded(dek, s.DEKs.Current, pad)
}

// ReadManifest decrypts the store manifest and enforces rollback protection (S4):
// it aborts loudly if the manifest generation is below the locally remembered
// high-water mark.
func (s *Session) ReadManifest() (*manifest.Manifest, error) {
	if !s.Store.Exists(store.ManifestFile) {
		return nil, fmt.Errorf("encrypted store has no manifest")
	}
	blob, err := s.Store.ReadFile(store.ManifestFile)
	if err != nil {
		return nil, err
	}
	m, err := manifest.Decrypt(blob, s.lookupDEK)
	if err != nil {
		return nil, err
	}
	state, err := s.repo.LoadState()
	if err != nil {
		return nil, err
	}
	if m.Generation < state.LastGeneration {
		return nil, fmt.Errorf("ROLLBACK DETECTED: encrypted store is at generation %d but this client last saw %d.\n"+
			"This may be a malicious force-push, a rollback, or corruption. Refusing to proceed.\n"+
			"Investigate with `git cloak verify` before doing anything else", m.Generation, state.LastGeneration)
	}
	return m, nil
}

// advanceGeneration records a newly-accepted manifest generation as the local
// high-water mark (S4).
func (s *Session) advanceGeneration(gen uint64) error {
	return s.commitState(gen, "")
}
