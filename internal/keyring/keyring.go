// Package keyring stores the local X25519 identity key in a keyfile under the
// git-cloak config directory. Two backends are supported: an Argon2id-encrypted
// file (identity.enc, the secure default) and a plaintext file (identity.json,
// only with explicit opt-in). There is intentionally no OS-keychain backend: a
// pure-Go (no cgo) macOS Keychain store cannot avoid exposing the secret in
// process argv, so git-cloak uses keyfiles only.
package keyring

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/johans/git-cloak/internal/crypto"
)

const (
	encFile       = "identity.enc"
	plaintextFile = "identity.json"
)

// ErrNoIdentity is returned when no identity keyfile exists.
var ErrNoIdentity = errors.New("keyring: no identity found (run `git cloak init`)")

// Backend selects how an identity is stored.
type Backend int

const (
	// BackendEncrypted writes identity.enc protected by an Argon2id passphrase.
	BackendEncrypted Backend = iota
	// BackendPlaintext writes identity.json with no protection (insecure).
	BackendPlaintext
)

// ConfigDir is the directory holding identity keyfiles. GIT_CLOAK_HOME overrides
// it (used by tests and to simulate separate machines); otherwise it follows
// XDG_CONFIG_HOME or ~/.config/git-cloak.
func ConfigDir() string {
	if d := os.Getenv("GIT_CLOAK_HOME"); d != "" {
		return d
	}
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "git-cloak")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".config", "git-cloak")
}

func encPath() string       { return filepath.Join(ConfigDir(), encFile) }
func plaintextPath() string { return filepath.Join(ConfigDir(), plaintextFile) }

// Exists reports whether any identity keyfile is present.
func Exists() bool {
	if _, err := os.Stat(encPath()); err == nil {
		return true
	}
	if _, err := os.Stat(plaintextPath()); err == nil {
		return true
	}
	return false
}

type plaintextIdentity struct {
	Private string `json:"private"`
	Public  string `json:"public"`
}

// Load reads the local identity, auto-detecting the backend. For the encrypted
// backend it obtains the passphrase from prompt (CLOAK_PASSPHRASE or terminal).
func Load(prompt Prompter) (crypto.Identity, error) {
	var id crypto.Identity
	if data, err := os.ReadFile(encPath()); err == nil {
		pass, perr := prompt("Enter git-cloak identity passphrase: ", false)
		if perr != nil {
			return id, perr
		}
		return crypto.DecryptIdentity(data, pass)
	}
	if data, err := os.ReadFile(plaintextPath()); err == nil {
		var pi plaintextIdentity
		if err := json.Unmarshal(data, &pi); err != nil {
			return id, fmt.Errorf("keyring: corrupt %s: %w", plaintextFile, err)
		}
		priv, err := hex.DecodeString(pi.Private)
		if err != nil || len(priv) != 32 {
			return id, fmt.Errorf("keyring: invalid private key in %s", plaintextFile)
		}
		pub, err := hex.DecodeString(pi.Public)
		if err != nil || len(pub) != 32 {
			return id, fmt.Errorf("keyring: invalid public key in %s", plaintextFile)
		}
		copy(id.Private[:], priv)
		copy(id.Public[:], pub)
		return id, nil
	}
	return id, ErrNoIdentity
}

// Save persists an identity using the chosen backend. The encrypted backend
// prompts for a passphrase (with confirmation).
func Save(id crypto.Identity, backend Backend, prompt Prompter) error {
	dir := ConfigDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	switch backend {
	case BackendPlaintext:
		pi := plaintextIdentity{
			Private: hex.EncodeToString(id.Private[:]),
			Public:  hex.EncodeToString(id.Public[:]),
		}
		data, err := json.MarshalIndent(pi, "", "  ")
		if err != nil {
			return err
		}
		return writeKeyfile(plaintextPath(), append(data, '\n'))
	case BackendEncrypted:
		pass, err := prompt("Set a passphrase to protect the identity: ", true)
		if err != nil {
			return err
		}
		if len(pass) == 0 {
			return errors.New("keyring: empty passphrase not allowed (use --insecure-plaintext-identity if you really want no protection)")
		}
		blob, err := crypto.EncryptIdentity(id, pass)
		if err != nil {
			return err
		}
		return writeKeyfile(encPath(), blob)
	default:
		return fmt.Errorf("keyring: unknown backend %d", backend)
	}
}

// GenerateAndSave creates a new identity and persists it, returning the identity.
// It refuses to overwrite an existing keyfile.
func GenerateAndSave(backend Backend, prompt Prompter) (crypto.Identity, error) {
	if Exists() {
		return crypto.Identity{}, errors.New("keyring: identity already exists; refusing to overwrite")
	}
	id, err := crypto.GenerateIdentity()
	if err != nil {
		return id, err
	}
	if err := Save(id, backend, prompt); err != nil {
		return id, err
	}
	return id, nil
}

func writeKeyfile(path string, data []byte) error {
	// 0600: secret material readable only by the owner (S5).
	return os.WriteFile(path, data, 0o600)
}
