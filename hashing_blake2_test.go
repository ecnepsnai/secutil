package secutil_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/ecnepsnai/secutil"
)

func TestHashingBLAKE2256(t *testing.T) {
	t.Parallel()

	expected := "733ec559845c8942ee01dcbba29ef7a44e31bc38a6184bc7f044155f7a3ec0f8"
	result := secutil.Hashing.BLAKE2_256.HashString("hunter2")

	if expected != result {
		t.Errorf("Invalid BLAKE2-256 hash. Expected '%s' got '%s'", expected, result)
	}
}

func TestHashingBLAKE2384(t *testing.T) {
	t.Parallel()

	expected := "ee799db986e67c68efb90eb8adf5687a7c4ca68d9f5b41b4c8aedc4cfb8d8302c64d62e03610e12c3b5507df3a996578"
	result := secutil.Hashing.BLAKE2_384.HashString("hunter2")

	if expected != result {
		t.Errorf("Invalid BLAKE2-384 hash. Expected '%s' got '%s'", expected, result)
	}
}

func TestHashingBLAKE2512(t *testing.T) {
	t.Parallel()

	expected := "2874646084422325e4870ae232783740d99abf25ef8393f4419392a72894e4146b058a8c42ed1104bab750148c14f7b6ee51b83d2ca1c0a55f38b306c099bf17"
	result := secutil.Hashing.BLAKE2_512.HashString("hunter2")

	if expected != result {
		t.Errorf("Invalid BLAKE2-512 hash. Expected '%s' got '%s'", expected, result)
	}
}

func TestHashingBLAKE2256Null(t *testing.T) {
	t.Parallel()

	expected, _ := hex.DecodeString("0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8")
	result := secutil.Hashing.BLAKE2_256.Hash([]byte{})

	if !bytes.Equal(expected, result) {
		t.Errorf("Invalid hash. Expected %x got %x", expected, result)
	}
}

func TestHashingBLAKE2384Null(t *testing.T) {
	t.Parallel()

	expected, _ := hex.DecodeString("b32811423377f52d7862286ee1a72ee540524380fda1724a6f25d7978c6fd3244a6caf0498812673c5e05ef583825100")
	result := secutil.Hashing.BLAKE2_384.Hash([]byte{})

	if !bytes.Equal(expected, result) {
		t.Errorf("Invalid hash. Expected %x got %x", expected, result)
	}
}

func TestHashingBLAKE2512Null(t *testing.T) {
	t.Parallel()

	expected, _ := hex.DecodeString("786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce")
	result := secutil.Hashing.BLAKE2_512.Hash([]byte{})

	if !bytes.Equal(expected, result) {
		t.Errorf("Invalid hash. Expected %x got %x", expected, result)
	}
}
