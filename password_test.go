package secutil_test

import (
	"bytes"
	"testing"

	"github.com/ecnepsnai/secutil"
)

var userPassword = []byte("hunter2")

func TestPasswordHash(t *testing.T) {
	t.Parallel()

	hash, err := secutil.HashPassword(userPassword)
	if err != nil {
		t.Fatalf("Unable to hash password: %s", err.Error())
	}

	if !hash.Compare(userPassword) {
		t.Fatalf("Password verification failed with correct password")
	}
	if hash.Compare([]byte("incorrect")) {
		t.Fatalf("Password validation succeeded with incorrect password")
	}
	if bytes.Equal([]byte(*hash), userPassword) {
		t.Fatalf("Hashed password was equal to raw password")
	}
}

func TestPasswordHashBCrypt(t *testing.T) {
	t.Parallel()

	hash, err := secutil.HashPasswordAlgorithm(userPassword, secutil.HashingAlgorithmBCrypt)
	if err != nil {
		t.Fatalf("Unable to hash password: %s", err.Error())
	}

	if !hash.Compare(userPassword) {
		t.Fatalf("Password verification failed with correct password")
	}
	if hash.Compare([]byte("incorrect")) {
		t.Fatalf("Password validation succeeded with incorrect password")
	}
	if bytes.Equal([]byte(*hash), userPassword) {
		t.Fatalf("Hashed password was equal to raw password")
	}
}

func TestPasswordHashArgon2id(t *testing.T) {
	t.Parallel()

	hash, err := secutil.HashPasswordAlgorithm(userPassword, secutil.HashingAlgorithmArgon2id)
	if err != nil {
		t.Fatalf("Unable to hash password: %s", err.Error())
	}

	if !hash.Compare(userPassword) {
		t.Fatalf("Password verification failed with correct password")
	}
	if hash.Compare([]byte("incorrect")) {
		t.Fatalf("Password validation succeeded with incorrect password")
	}
	if bytes.Equal([]byte(*hash), userPassword) {
		t.Fatalf("Hashed password was equal to raw password")
	}
}

func TestPasswordHashPBKDF2(t *testing.T) {
	t.Parallel()

	hash, err := secutil.HashPasswordAlgorithm(userPassword, secutil.HashingAlgorithmPBKDF2)
	if err != nil {
		t.Fatalf("Unable to hash password: %s", err.Error())
	}

	if !hash.Compare(userPassword) {
		t.Fatalf("Password verification failed with correct password")
	}
	if hash.Compare([]byte("incorrect")) {
		t.Fatalf("Password validation succeeded with incorrect password")
	}
	if bytes.Equal([]byte(*hash), userPassword) {
		t.Fatalf("Hashed password was equal to raw password")
	}
}

func TestPasswordUpgradeBCrypt(t *testing.T) {
	t.Parallel()

	oldHash, err := secutil.HashPasswordAlgorithm(userPassword, secutil.HashingAlgorithmBCrypt)
	if err != nil {
		t.Fatalf("Unable to hash password: %s", err.Error())
	}

	newHash := oldHash.Upgrade(userPassword)
	if newHash == nil {
		t.Fatalf("Error upgrading password")
	}

	if !newHash.Compare(userPassword) {
		t.Fatalf("Password verification failed with correct password")
	}
	if newHash.Compare([]byte("incorrect")) {
		t.Fatalf("Password validation succeeded with incorrect password")
	}
}

func TestPasswordUpgradePBKDF2(t *testing.T) {
	t.Parallel()

	oldHash, err := secutil.HashPasswordAlgorithm(userPassword, secutil.HashingAlgorithmPBKDF2)
	if err != nil {
		t.Fatalf("Unable to hash password: %s", err.Error())
	}

	newHash := oldHash.Upgrade(userPassword)
	if newHash == nil {
		t.Fatalf("Error upgrading password")
	}

	if !newHash.Compare(userPassword) {
		t.Fatalf("Password verification failed with correct password")
	}
	if newHash.Compare([]byte("incorrect")) {
		t.Fatalf("Password validation succeeded with incorrect password")
	}
}

func TestPasswordUnknownHashingAlgorithm(t *testing.T) {
	t.Parallel()

	hash, err := secutil.HashPasswordAlgorithm(userPassword, secutil.HashingAlgorithm("MD5"))
	if err == nil {
		t.Fatalf("No error seen when trying to hash password with unknown algorithm")
	}

	if hash != nil {
		t.Fatalf("Hash returned for invlaid algorithm")
	}

	defer func() {
		recover()
	}()

	unknownHash := secutil.HashedPassword([]byte("X$acab$blm"))
	if unknownHash.Compare(userPassword) {
		t.Fatalf("Should not return true for unknown algorithm")
	}
	t.Fatalf("No panic seen when one expected")
}

func TestPasswordCompareUnknownType(t *testing.T) {
	t.Parallel()

	// This is supposed to panic
	defer func() {
		recover()
	}()

	whatEvenIsThis := secutil.HashedPassword([]byte("DOGS_ARE_VERY_GOOD"))
	whatEvenIsThis.Algorithm()
	t.Fatalf("No panic seen when one expected")
}

func TestPasswordFuzzBCrypt(t *testing.T) {
	t.Parallel()

	p := []byte(secutil.HashingAlgorithmBCrypt)
	p = append(p, secutil.RandomBytes(16)...)
	hash := secutil.HashedPassword(p)

	result := hash.Compare(secutil.RandomBytes(16))
	if result {
		t.Fatalf("Unexpected hash result for fuzzed data - THIS IS BAD!")
	}
}

func TestPasswordFuzzArgon2id(t *testing.T) {
	t.Parallel()

	p := []byte(secutil.HashingAlgorithmArgon2id)
	p = append(p, secutil.RandomBytes(16)...)
	hash := secutil.HashedPassword(p)

	result := hash.Compare(secutil.RandomBytes(16))
	if result {
		t.Fatalf("Unexpected hash result for fuzzed data - THIS IS BAD!")
	}
}

func TestPasswordFuzzPBKDF2(t *testing.T) {
	t.Parallel()

	p := []byte(secutil.HashingAlgorithmPBKDF2)
	p = append(p, secutil.RandomBytes(16)...)
	hash := secutil.HashedPassword(p)

	result := hash.Compare(secutil.RandomBytes(16))
	if result {
		t.Fatalf("Unexpected hash result for fuzzed data - THIS IS BAD!")
	}
}
