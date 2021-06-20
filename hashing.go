package secutil

type IHashing interface {
	Hash(in []byte) []byte
	HashString(in string) string
}

// HashingSHA is an implementation of the IHashing interface for SHA hashing
type HashingSHA struct {
	Len int
}

// HashingBLAKE2 is an implementation of the IHashing interface for BLAKE2b hashing
type HashingBLAKE2 struct {
	Len int
}

// Hashing provides access to a standard interface for cryptographic hashing
var Hashing = struct {
	SHA_256    IHashing
	SHA_512    IHashing
	BLAKE2_256 IHashing
	BLAKE2_384 IHashing
	BLAKE2_512 IHashing
}{
	SHA_256:    HashingSHA{256},
	SHA_512:    HashingSHA{512},
	BLAKE2_256: HashingBLAKE2{256},
	BLAKE2_384: HashingBLAKE2{384},
	BLAKE2_512: HashingBLAKE2{512},
}
