package secutil_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/ecnepsnai/secutil"
)

func TestHashSHA256(t *testing.T) {
	t.Parallel()

	expected := "f52fbd32b2b3b86ff88ef6c490628285f482af15ddcb29541f94bcf526a3f6c7"
	result := secutil.HashSHA256String("hunter2")

	if expected != result {
		t.Errorf("Invalid SHA-256 hash")
	}
}

func TestHashSHA512(t *testing.T) {
	t.Parallel()

	expected := "6b97ed68d14eb3f1aa959ce5d49c7dc612e1eb1dafd73b1e705847483fd6a6c809f2ceb4e8df6ff9984c6298ff0285cace6614bf8daa9f0070101b6c89899e22"
	result := secutil.HashSHA512String("hunter2")

	if expected != result {
		t.Errorf("Invalid SHA-512 hash")
	}
}

func TestHashSHA256Null(t *testing.T) {
	t.Parallel()

	expected, _ := hex.DecodeString("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	result := secutil.HashSHA256([]byte{})

	if !bytes.Equal(expected, result) {
		t.Errorf("Invalid hash. Expected %x got %x", expected, result)
	}
}

func TestHashSHA512Null(t *testing.T) {
	t.Parallel()

	expected, _ := hex.DecodeString("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")
	result := secutil.HashSHA512([]byte{})

	if !bytes.Equal(expected, result) {
		t.Errorf("Invalid hash. Expected %x got %x", expected, result)
	}
}
