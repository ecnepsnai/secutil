package secutil

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
)

// Hash will hash the given data with SHA and return hash bytes
func (t HashingSHA) Hash(in []byte) []byte {
	var hasher hash.Hash
	switch t.Len {
	case 256:
		hasher = sha256.New()
	case 512:
		hasher = sha512.New()
	default:
		panic("invalid SHA hash length")
	}

	hasher.Write(in)
	return hasher.Sum(nil)
}

// HashString will hash the given string with SHA and return a hex string
func (t HashingSHA) HashString(in string) string {
	return hex.EncodeToString(t.Hash([]byte(in)))
}
