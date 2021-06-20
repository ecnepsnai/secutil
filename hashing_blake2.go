package secutil

import (
	"encoding/hex"
	"hash"

	"golang.org/x/crypto/blake2b"
)

// Hash will hash the given data with BLAKE2b and return hash bytes
func (t HashingBLAKE2) Hash(in []byte) []byte {
	var hasher hash.Hash
	var err error
	switch t.Len {
	case 256:
		hasher, err = blake2b.New256(nil)
	case 384:
		hasher, err = blake2b.New384(nil)
	case 512:
		hasher, err = blake2b.New512(nil)
	default:
		panic("invalid BLAKE2 hash length")
	}
	if err != nil {
		panic(err.Error())
	}

	hasher.Write(in)
	return hasher.Sum(nil)
}

// HashString will hash the given string with BLAKE2b and return a hex string
func (t HashingBLAKE2) HashString(in string) string {
	return hex.EncodeToString(t.Hash([]byte(in)))
}
