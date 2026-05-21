package store

import (
	"encoding/json"
	"fmt"

	"github.com/johans/git-cloak/internal/crypto"
)

// Config is cloak.json: cleartext metadata that lets a fresh clone interpret the
// rest of the store. It is audited to contain zero secrets — recipient ids are
// public key hashes (§7.1).
type Config struct {
	Format         int    `json:"format"`
	Cipher         string `json:"cipher"`
	ChunkSize      int    `json:"chunk_size"`
	PackSplitBytes int64  `json:"pack_split_bytes"`
	KDF            string `json:"kdf"`
	KeyWrap        string `json:"keywrap"`
	DEKGenerations int    `json:"dek_generations"`
	// ManifestPadding, if > 0, rounds the encrypted manifest up to a multiple of
	// this many bytes to obscure ref/pack counts (opt-in, off by default — N2).
	ManifestPadding int `json:"manifest_padding,omitempty"`
	// Recipients holds each recipient's public identity key as a cloak1… token.
	// Public keys (and the ids derived from them) are safe to expose (§7.1) and
	// are needed to re-wrap the DEK on add-recipient and rotate-key.
	Recipients []string `json:"recipients"`
}

// Default GitHub-aware sizing.
const (
	// DefaultPackSplitBytes targets ~90 MiB ciphertext chunks, comfortably under
	// GitHub's 100 MB per-file hard limit (§7.3).
	DefaultPackSplitBytes = 94371840
)

// DefaultConfig returns a fresh cloak.json for a new store with the given
// initial recipients.
func DefaultConfig(recipients []string) *Config {
	return &Config{
		Format:         1,
		Cipher:         "xchacha20poly1305-stream",
		ChunkSize:      crypto.DefaultChunkSize,
		PackSplitBytes: DefaultPackSplitBytes,
		KDF:            "hkdf-sha256",
		KeyWrap:        "x25519-sealedbox",
		DEKGenerations: 1,
		Recipients:     recipients,
	}
}

// ReadConfig loads cloak.json from the store.
func (s *Store) ReadConfig() (*Config, error) {
	data, err := s.ReadFile(ConfigFile)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("store: corrupt %s: %w", ConfigFile, err)
	}
	if c.ChunkSize <= 0 {
		c.ChunkSize = crypto.DefaultChunkSize
	}
	if c.PackSplitBytes <= 0 {
		c.PackSplitBytes = DefaultPackSplitBytes
	}
	return &c, nil
}

// WriteConfig writes cloak.json (pretty-printed for human auditability).
func (s *Store) WriteConfig(c *Config) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return s.WriteFile(ConfigFile, append(data, '\n'))
}

// HasConfig reports whether the store has been initialized.
func (s *Store) HasConfig() bool { return s.Exists(ConfigFile) }
