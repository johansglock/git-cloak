package store

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/johans/git-cloak/internal/crypto"
)

// WritePack encrypts a git packfile (read from plaintext) into one or more
// numbered chunk files under packs/. Each chunk file is an independent STREAM
// blob with its own HKDF subkey (salted by packid||chunkIndex, S3) and its own
// random nonce prefix, and is sized to stay under splitBytes so GitHub accepts it
// (§7.3). Memory use is bounded by chunkSize regardless of pack size (§14).
//
// Returns the number of chunk files written (always >= 1).
func (s *Store) WritePack(packID [crypto.SaltIDLen]byte, dek []byte, dekGen uint32, plaintext io.Reader, splitBytes int64, chunkSize int) (int, error) {
	if chunkSize <= 0 {
		chunkSize = crypto.DefaultChunkSize
	}
	// Largest whole-plaintext budget whose ciphertext fits under splitBytes:
	// header + nInner*(chunkSize+tag) <= splitBytes.
	maxInner := (splitBytes - int64(crypto.HeaderLen)) / int64(chunkSize+crypto.TagLen)
	if maxInner < 1 {
		return 0, fmt.Errorf("store: pack_split_bytes %d too small for chunk size %d", splitBytes, chunkSize)
	}
	plainPerFile := maxInner * int64(chunkSize)

	packHex := hex.EncodeToString(packID[:])
	br := bufio.NewReaderSize(plaintext, chunkSize+64)

	idx := 0
	for {
		key, err := crypto.DeriveKey(dek, crypto.PackSalt(packID, uint32(idx)), crypto.InfoPack)
		if err != nil {
			return 0, err
		}
		hdr, err := crypto.NewPackChunkHeader(packID, uint32(idx), dekGen, uint32(chunkSize))
		if err != nil {
			return 0, err
		}

		rel := PackChunkPath(packHex, idx)
		fpath := s.path(rel)
		if err := os.MkdirAll(s.path(PacksDir), 0o700); err != nil {
			return 0, err
		}
		f, err := os.OpenFile(fpath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return 0, err
		}
		bw := bufio.NewWriter(f)
		limited := io.LimitReader(br, plainPerFile)
		if err := crypto.SealStream(bw, limited, key, hdr); err != nil {
			f.Close()
			return 0, err
		}
		if err := bw.Flush(); err != nil {
			f.Close()
			return 0, err
		}
		if err := f.Close(); err != nil {
			return 0, err
		}

		// Assert we stayed under the limit (§13: a chunk over the limit is a bug).
		if fi, err := os.Stat(fpath); err == nil && fi.Size() > splitBytes {
			return 0, fmt.Errorf("store: pack chunk %d is %d bytes, exceeds split limit %d (bug)", idx, fi.Size(), splitBytes)
		}

		idx++
		// More plaintext remaining?
		if _, perr := br.Peek(1); perr == io.EOF {
			break
		} else if perr != nil {
			return 0, perr
		}
	}
	return idx, nil
}

// ReadPack decrypts all chunk files of a pack in order and streams the
// reconstructed packfile plaintext to w. dek must be the key for the pack's DEK
// generation. Fails closed on any AEAD failure, missing chunk, or header
// mismatch.
func (s *Store) ReadPack(packIDHex string, chunks int, dekGen uint32, dek []byte, w io.Writer) error {
	wantID, err := hex.DecodeString(packIDHex)
	if err != nil || len(wantID) != crypto.SaltIDLen {
		return fmt.Errorf("store: invalid pack id %q", packIDHex)
	}
	for idx := 0; idx < chunks; idx++ {
		rel := PackChunkPath(packIDHex, idx)
		f, err := os.Open(s.path(rel))
		if err != nil {
			return fmt.Errorf("store: missing pack chunk %s: %w", rel, err)
		}
		br := bufio.NewReader(f)
		hdr, err := crypto.ReadHeader(br)
		if err != nil {
			f.Close()
			return fmt.Errorf("store: %s: %w", rel, err)
		}
		if hex.EncodeToString(hdr.SaltID[:]) != packIDHex {
			f.Close()
			return fmt.Errorf("store: %s: pack id mismatch (swapped chunk?)", rel)
		}
		if int(hdr.ChunkIndex) != idx {
			f.Close()
			return fmt.Errorf("store: %s: chunk index mismatch (reordered?)", rel)
		}
		if hdr.DEKGen != dekGen {
			f.Close()
			return fmt.Errorf("store: %s: dek generation mismatch", rel)
		}
		key, err := crypto.DeriveKey(dek, crypto.PackSalt(hdr.SaltID, hdr.ChunkIndex), crypto.InfoPack)
		if err != nil {
			f.Close()
			return err
		}
		if err := crypto.OpenStream(w, br, key, hdr); err != nil {
			f.Close()
			return fmt.Errorf("store: %s: %w", rel, err)
		}
		f.Close()
	}
	return nil
}

// VerifyPack decrypts every chunk of a pack and discards the output, returning an
// error if any AEAD tag or header check fails (used by `git cloak verify`).
func (s *Store) VerifyPack(packIDHex string, chunks int, dekGen uint32, dek []byte) error {
	return s.ReadPack(packIDHex, chunks, dekGen, dek, io.Discard)
}
