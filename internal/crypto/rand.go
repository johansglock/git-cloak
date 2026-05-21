package crypto

import (
	"crypto/rand"
	"encoding/binary"
)

// RandomNoncePrefix returns a fresh random per-blob nonce prefix.
func RandomNoncePrefix() ([NoncePrefixLen]byte, error) {
	var p [NoncePrefixLen]byte
	_, err := rand.Read(p[:])
	return p, err
}

// RandomPackID returns a random 128-bit pack id. Random (not content-derived) so
// the encrypted store reveals no equality between packs across repositories.
func RandomPackID() ([SaltIDLen]byte, error) {
	var id [SaltIDLen]byte
	_, err := rand.Read(id[:])
	return id, err
}

// NewPackChunkHeader builds a header for one pack chunk file with a fresh nonce.
func NewPackChunkHeader(packID [SaltIDLen]byte, chunkIndex, dekGen uint32, chunkSize uint32) (BlobHeader, error) {
	np, err := RandomNoncePrefix()
	if err != nil {
		return BlobHeader{}, err
	}
	if chunkSize == 0 {
		chunkSize = DefaultChunkSize
	}
	return BlobHeader{
		Version:     FormatVersion,
		Cipher:      CipherXChaCha,
		ChunkSize:   chunkSize,
		DEKGen:      dekGen,
		SaltID:      packID,
		ChunkIndex:  chunkIndex,
		NoncePrefix: np,
	}, nil
}

// NewManifestHeader builds a header for the manifest blob with a fresh nonce. The
// manifest's HKDF salt is its generation counter, packed into the SaltID field.
func NewManifestHeader(generation uint64, dekGen uint32, chunkSize uint32) (BlobHeader, error) {
	np, err := RandomNoncePrefix()
	if err != nil {
		return BlobHeader{}, err
	}
	if chunkSize == 0 {
		chunkSize = DefaultChunkSize
	}
	return BlobHeader{
		Version:     FormatVersion,
		Cipher:      CipherXChaCha,
		ChunkSize:   chunkSize,
		DEKGen:      dekGen,
		SaltID:      GenerationSaltID(generation),
		ChunkIndex:  0,
		NoncePrefix: np,
	}, nil
}

// ManifestGenerationFromHeader recovers the generation counter encoded in a
// manifest blob header's SaltID by GenerationSaltID.
func ManifestGenerationFromHeader(h BlobHeader) uint64 {
	return binary.BigEndian.Uint64(h.SaltID[:8])
}
