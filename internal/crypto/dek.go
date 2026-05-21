package crypto

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

// DEK is one generation of the repository data-encryption key.
type DEK struct {
	Generation uint32
	Key        [KeyLen]byte
}

// DEKSet is the full set of repository DEK generations that a recipient is
// entitled to, together with the current (newest) generation used to encrypt new
// blobs. The whole set is what gets sealed into each recipient's wrap file, so a
// recipient can read both new and historical packs.
type DEKSet struct {
	Current uint32
	Keys    []DEK
}

const dekSetVersion = 1

// NewDEK creates a fresh random DEK at generation 1 and returns a one-element set.
func NewDEK() (DEKSet, error) {
	var k [KeyLen]byte
	if _, err := rand.Read(k[:]); err != nil {
		return DEKSet{}, err
	}
	return DEKSet{Current: 1, Keys: []DEK{{Generation: 1, Key: k}}}, nil
}

// Rotate appends a new random DEK at the next generation and makes it current.
// Older generations are retained so previously-pushed packs remain readable.
func (s DEKSet) Rotate() (DEKSet, error) {
	var k [KeyLen]byte
	if _, err := rand.Read(k[:]); err != nil {
		return DEKSet{}, err
	}
	next := s.Current + 1
	out := DEKSet{Current: next, Keys: make([]DEK, len(s.Keys), len(s.Keys)+1)}
	copy(out.Keys, s.Keys)
	out.Keys = append(out.Keys, DEK{Generation: next, Key: k})
	return out, nil
}

// Get returns the key for a specific generation.
func (s DEKSet) Get(gen uint32) ([]byte, error) {
	for _, d := range s.Keys {
		if d.Generation == gen {
			key := d.Key
			return key[:], nil
		}
	}
	return nil, fmt.Errorf("crypto: DEK generation %d not available", gen)
}

// CurrentKey returns the current generation's key.
func (s DEKSet) CurrentKey() ([]byte, error) {
	return s.Get(s.Current)
}

// Marshal serializes the DEK set to a stable binary form for sealing.
func (s DEKSet) Marshal() []byte {
	b := make([]byte, 1+4+4+len(s.Keys)*(4+KeyLen))
	b[0] = dekSetVersion
	binary.BigEndian.PutUint32(b[1:5], s.Current)
	binary.BigEndian.PutUint32(b[5:9], uint32(len(s.Keys)))
	off := 9
	for _, d := range s.Keys {
		binary.BigEndian.PutUint32(b[off:off+4], d.Generation)
		copy(b[off+4:off+4+KeyLen], d.Key[:])
		off += 4 + KeyLen
	}
	return b
}

// ParseDEKSet deserializes a DEK set produced by Marshal.
func ParseDEKSet(b []byte) (DEKSet, error) {
	if len(b) < 9 {
		return DEKSet{}, errors.New("crypto: short DEK set")
	}
	if b[0] != dekSetVersion {
		return DEKSet{}, fmt.Errorf("crypto: unsupported DEK set version %d", b[0])
	}
	cur := binary.BigEndian.Uint32(b[1:5])
	n := binary.BigEndian.Uint32(b[5:9])
	if int(n) > (len(b)-9)/(4+KeyLen) {
		return DEKSet{}, errors.New("crypto: corrupt DEK set length")
	}
	set := DEKSet{Current: cur, Keys: make([]DEK, 0, n)}
	off := 9
	for i := uint32(0); i < n; i++ {
		var d DEK
		d.Generation = binary.BigEndian.Uint32(b[off : off+4])
		copy(d.Key[:], b[off+4:off+4+KeyLen])
		set.Keys = append(set.Keys, d)
		off += 4 + KeyLen
	}
	return set, nil
}
