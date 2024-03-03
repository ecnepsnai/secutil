package secutil

import (
	"bufio"
	"bytes"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"
)

// Encrypt will encrypt the given data using ChaCha20-Poly1305 with the given passphrase.
// The passphrase can be a user provided value, and is hashed using scrypt before being used.
//
// Will return error if an empty passphrase or data is provided.
func (t EncryptionChaCha20Poly1305) Encrypt(data []byte, passphrase string) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("cannot encrypt nothing - data length 0")
	}
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("passphrase is required")
	}

	return t.EncryptKey(data, t.PassphraseToKey(passphrase))
}

// EncryptKey will encrypt the given data using ChaCha20-Poly1305 with the given 32-byte key.
//
// Will return error if an invaid key or data is provided.
func (t EncryptionChaCha20Poly1305) EncryptKey(data []byte, key []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("cannot encrypt nothing - data length 0")
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key")
	}

	block, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	nonce := RandomBytes(uint16(block.NonceSize()))
	ciphertext := block.Seal(nil, nonce, data, nil)

	var writer bytes.Buffer
	if _, err := writer.Write(nonce); err != nil {
		return nil, err
	}
	if _, err := writer.Write(ciphertext); err != nil {
		return nil, err
	}

	return writer.Bytes(), nil
}

// Decrypt will decrypt the given encrypted data using ChaCha20-Poly1305 with the given passphrase.
// The passphrase can be a user provided value, and is hashed using scrypt before being used.
//
// Will return error if an empty passphrase or data is provided.
func (t EncryptionChaCha20Poly1305) Decrypt(data []byte, passphrase string) ([]byte, error) {
	if len(data) < 24 {
		return nil, fmt.Errorf("invalid encrypted data")
	}
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("passphrase is required")
	}

	return t.DecryptKey(data, t.PassphraseToKey(passphrase))
}

// DecryptKey will decrypt the given encrypted data using ChaCha20-Poly1305 with the given 32-byte key.
//
// Will return error if an invaid key or data is provided.
func (t EncryptionChaCha20Poly1305) DecryptKey(data []byte, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key")
	}
	if len(data) < 24 {
		return nil, fmt.Errorf("invalid encrypted data")
	}

	r := bufio.NewReader(bytes.NewReader(data))
	nonce := make([]byte, 24)
	if _, err := io.ReadFull(r, nonce); err != nil {
		return nil, err
	}

	ciphertext, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	block, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	rawdata, err := block.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return rawdata, nil
}

// PassphraseToKey generates a 32-byte key from the given passphrase
func (t EncryptionChaCha20Poly1305) PassphraseToKey(passphrase string) []byte {
	key, err := scrypt.Key([]byte(passphrase), nil, 32768, 8, 1, 32)
	if err != nil {
		panic(err)
	}
	if len(key) != 32 {
		panic("invalid key length after hashing")
	}
	return key
}
