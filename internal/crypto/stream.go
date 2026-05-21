package crypto

import (
	"bufio"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// SealStream encrypts all plaintext read from r and writes a complete STREAM blob
// to w: the header followed by a sequence of AEAD-sealed chunks. The plaintext is
// split into fixed h.ChunkSize chunks; chunk i uses nonce (NoncePrefix ||
// uint32_be(i) || finalFlag) and AAD (header || uint32_be(i) || finalFlag). The
// last chunk is marked with finalFlag=0x01, which binds the blob against
// truncation (S2). The caller supplies the subkey (derive it with DeriveKey) and
// a header carrying a random NoncePrefix.
//
// Memory use is bounded by one chunk regardless of input size (S streaming).
func SealStream(w io.Writer, r io.Reader, key []byte, h BlobHeader) error {
	if h.ChunkSize == 0 {
		h.ChunkSize = DefaultChunkSize
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return err
	}
	hb := h.Marshal()
	if _, err := w.Write(hb); err != nil {
		return err
	}

	cs := int(h.ChunkSize)
	buf := make([]byte, cs)
	br := bufio.NewReaderSize(r, cs+64)

	var i uint32
	for {
		n, rerr := io.ReadFull(br, buf)
		final := false
		switch rerr {
		case nil:
			// Full chunk. Peek to learn whether any plaintext follows; if not,
			// this chunk is final.
			if _, perr := br.Peek(1); perr == io.EOF {
				final = true
			} else if perr != nil {
				return perr
			}
		case io.ErrUnexpectedEOF:
			final = true // short read => last chunk
		case io.EOF:
			// No bytes for this chunk. Only happens for empty input at i==0,
			// where we still emit a single final (empty) chunk.
			final = true
			n = 0
		default:
			return rerr
		}

		nonce := makeNonce(h.NoncePrefix, i, final)
		aad := makeAAD(hb, i, final)
		ct := aead.Seal(nil, nonce, buf[:n], aad)
		if _, err := w.Write(ct); err != nil {
			return err
		}
		i++
		if final {
			return nil
		}
	}
}

// OpenStream decrypts a STREAM blob body from r and writes the plaintext to w.
// The header must already have been read with ReadHeader and used to derive key.
// Decryption fails closed (returns an error and never emits trailing plaintext
// past a bad chunk) on any tamper, truncation, reorder, or wrong key.
func OpenStream(w io.Writer, r io.Reader, key []byte, h BlobHeader) error {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return err
	}
	hb := h.Marshal()
	cs := int(h.ChunkSize)
	encChunk := cs + TagLen
	buf := make([]byte, encChunk)
	br := bufio.NewReaderSize(r, encChunk+64)

	var i uint32
	for {
		n, rerr := io.ReadFull(br, buf)
		final := false
		switch rerr {
		case nil:
			if _, perr := br.Peek(1); perr == io.EOF {
				final = true
			} else if perr != nil {
				return perr
			}
		case io.ErrUnexpectedEOF:
			final = true
		case io.EOF:
			// A blob always has at least one chunk; reaching EOF before any
			// ciphertext means the body was truncated away entirely.
			return ErrTruncated
		default:
			return rerr
		}

		if n < TagLen {
			return ErrTruncated
		}
		nonce := makeNonce(h.NoncePrefix, i, final)
		aad := makeAAD(hb, i, final)
		pt, oerr := aead.Open(nil, nonce, buf[:n], aad)
		if oerr != nil {
			return ErrAuthFailed
		}
		if _, err := w.Write(pt); err != nil {
			return err
		}
		i++
		if final {
			return nil
		}
	}
}

func makeNonce(prefix [NoncePrefixLen]byte, i uint32, final bool) []byte {
	n := make([]byte, chacha20poly1305.NonceSizeX) // 24
	copy(n[:NoncePrefixLen], prefix[:])
	binary.BigEndian.PutUint32(n[NoncePrefixLen:NoncePrefixLen+4], i)
	if final {
		n[NoncePrefixLen+4] = 0x01
	}
	return n
}

func makeAAD(header []byte, i uint32, final bool) []byte {
	aad := make([]byte, len(header)+5)
	copy(aad, header)
	binary.BigEndian.PutUint32(aad[len(header):len(header)+4], i)
	if final {
		aad[len(header)+4] = 0x01
	}
	return aad
}
