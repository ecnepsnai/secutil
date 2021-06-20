package secutil_test

import (
	"encoding/hex"
	"testing"

	"github.com/ecnepsnai/secutil"
)

func TestEncryptionCHACHA320POLY1305Encrypt(t *testing.T) {
	t.Parallel()

	data := []byte("Hello world!")
	passphrase := "hunter1"
	encryptedBytes, err := secutil.Encryption.CHACHA20_POLY1305.Encrypt(data, passphrase)
	if err != nil {
		t.Fatalf("Error encrypting bytes: %s", err.Error())
	}
	if encryptedBytes == nil || len(encryptedBytes) <= 0 {
		t.Fatalf("Encrypted bytes is empty")
	}
}

func TestEncryptionCHACHA320POLY1305Decrypt(t *testing.T) {
	t.Parallel()

	encryptedBytes, err := hex.DecodeString("a18fa04163d4dfc82edec518e6231e405ecbac2438d1e8e68047ab4f79cae80ae420ce00da8b95f3f9849d75f04334f8e9fc6787")
	if err != nil {
		t.Fatalf("Invalid encrypted bytes: %s", err.Error())
	}
	if len(encryptedBytes) <= 0 {
		t.Fatalf("Encrypted bytes is empty")
	}
	passphrase := "hunter1"

	decryptedBytes, err := secutil.Encryption.CHACHA20_POLY1305.Decrypt(encryptedBytes, passphrase)
	if err != nil {
		t.Fatalf("Error decrypting bytes: %s", err.Error())
	}
	if decryptedBytes == nil || len(decryptedBytes) <= 0 {
		t.Fatalf("decrypted bytes is empty")
	}
	expected := "Hello world!"
	actual := string(decryptedBytes)
	if actual != expected {
		t.Fatalf("Incorrect plain-text value, expected '%s' got '%s'", expected, actual)
	}
}

func TestEncryptionCHACHA320POLY1305DecryptIncorrectPassphrase(t *testing.T) {
	t.Parallel()

	encryptedBytes, err := hex.DecodeString("a18fa04163d4dfc82edec518e6231e405ecbac2438d1e8e68047ab4f79cae80ae420ce00da8b95f3f9849d75f04334f8e9fc6787")
	if err != nil {
		t.Fatalf("Invalid encrypted bytes: %s", err.Error())
	}
	if len(encryptedBytes) <= 0 {
		t.Fatalf("Encrypted bytes is empty")
	}
	passphrase := "not correct :("

	decryptedBytes, err := secutil.Encryption.CHACHA20_POLY1305.Decrypt(encryptedBytes, passphrase)
	if err == nil {
		t.Fatalf("No error seen decrypting bytes with incorrect passphrase")
	}
	if decryptedBytes != nil {
		t.Fatalf("Decrypted bytes returned with incorrect passphrase")
	}
}

func TestEncryptionCHACHA320POLY1305EncryptBadParameters(t *testing.T) {
	var data []byte
	var err error

	// No data
	data, err = secutil.Encryption.CHACHA20_POLY1305.Encrypt([]byte{}, "hunter2")
	if err == nil {
		t.Fatalf("No error seen when trying to encrypt nothing")
	}
	if data != nil {
		t.Fatalf("Unexpected data")
	}

	// No passphrase
	data, err = secutil.Encryption.CHACHA20_POLY1305.Encrypt([]byte("foo"), "")
	if err == nil {
		t.Fatalf("No error seen when trying to encrypt without passphrase")
	}
	if data != nil {
		t.Fatalf("Unexpected data")
	}

	// Invalid key
	data, err = secutil.Encryption.CHACHA20_POLY1305.EncryptKey([]byte("foo"), []byte("bar"))
	if err == nil {
		t.Fatalf("No error seen when trying to encrypt with invalid key")
	}
	if data != nil {
		t.Fatalf("Unexpected data")
	}

	// Incorrect data length
	data, err = secutil.Encryption.CHACHA20_POLY1305.EncryptKey([]byte{}, secutil.Encryption.CHACHA20_POLY1305.PassphraseToKey("hunter2"))
	if err == nil {
		t.Fatalf("No error seen when trying to encrypt incorrect data")
	}
	if data != nil {
		t.Fatalf("Unexpected data")
	}
}

func TestEncryptionCHACHA320POLY1305DecryptBadParameters(t *testing.T) {
	var data []byte
	var err error

	// No data
	data, err = secutil.Encryption.CHACHA20_POLY1305.Decrypt([]byte{}, "hunter2")
	if err == nil {
		t.Fatalf("No error seen when trying to decrypt nothing")
	}
	if data != nil {
		t.Fatalf("Unexpected data")
	}

	// No passphrase
	data, err = secutil.Encryption.CHACHA20_POLY1305.Decrypt(secutil.RandomBytes(32), "")
	if err == nil {
		t.Fatalf("No error seen when trying to decrypt without passphrase")
	}
	if data != nil {
		t.Fatalf("Unexpected data")
	}

	// Invalid key
	data, err = secutil.Encryption.CHACHA20_POLY1305.DecryptKey(secutil.RandomBytes(32), []byte("bar"))
	if err == nil {
		t.Fatalf("No error seen when trying to decrypt with invalid key")
	}
	if data != nil {
		t.Fatalf("Unexpected data")
	}

	// Incorrect data length
	data, err = secutil.Encryption.CHACHA20_POLY1305.DecryptKey(secutil.RandomBytes(6), secutil.Encryption.CHACHA20_POLY1305.PassphraseToKey("hunter2"))
	if err == nil {
		t.Fatalf("No error seen when trying to decrypt incorrect data")
	}
	if data != nil {
		t.Fatalf("Unexpected data")
	}
}

func TestEncryptionCHACHA320POLY1305DecryptFuzzedData(t *testing.T) {
	passphrase := secutil.RandomString(8)
	decryptedBytes, err := secutil.Encryption.CHACHA20_POLY1305.Decrypt(secutil.RandomBytes(16), passphrase)
	if err == nil {
		t.Fatalf("No error seen decrypting random data")
	}
	if decryptedBytes != nil {
		t.Fatalf("Decrypted bytes returned with random data")
	}
}
