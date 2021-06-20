package secutil

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"io/ioutil"

	"golang.org/x/crypto/scrypt"
)

// Encrypt will encrypt the given data using AES-256-GCM with the given passphrase.
// The passphrase can be a user provided value, and is hashed using scrypt before being used.
//
// Will return error if an empty passphrase or data is provided.
func (t EncryptionAES256GCM) Encrypt(data []byte, passphrase string) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("cannot encrypt nothing - data length 0")
	}
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("passphrase is required")
	}

	return t.EncryptKey(data, t.PassphraseToKey(passphrase))
}

// EncryptKey will encrypt the given data using AES-256-GCM with the given 32-byte key.
//
// Will return error if an invaid key or data is provided.
func (t EncryptionAES256GCM) EncryptKey(data []byte, key []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("cannot encrypt nothing - data length 0")
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	nonce := RandomBytes(12) // 12 is the standard nonce size for GCM
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, data, nil)

	var writer bytes.Buffer
	if _, err := writer.Write(nonce); err != nil {
		return nil, err
	}
	if _, err := writer.Write(ciphertext); err != nil {
		return nil, err
	}

	return writer.Bytes(), nil
}

// Decrypt will decrypt the given encrypted data using AES-256-GCM with the given passphrase.
// The passphrase can be a user provided value, and is hashed using scrypt before being used.
//
// Will return error if an empty passphrase or data is provided.
func (t EncryptionAES256GCM) Decrypt(data []byte, passphrase string) ([]byte, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("invalid encrypted data")
	}
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("passphrase is required")
	}

	return t.DecryptKey(data, t.PassphraseToKey(passphrase))
}

// DecryptKey will decrypt the given encrypted data using AES-256-GCM with the given 32-byte key.
//
// Will return error if an invaid key or data is provided.
func (t EncryptionAES256GCM) DecryptKey(data []byte, key []byte) ([]byte, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("invalid encrypted data")
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key")
	}

	r := bufio.NewReader(bytes.NewReader(data))
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(r, nonce); err != nil {
		return nil, err
	}

	ciphertext, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	rawdata, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return rawdata, nil
}

// PassphraseToKey generates a 32-byte key from the given passphrase
func (t EncryptionAES256GCM) PassphraseToKey(passphrase string) []byte {
	key, err := scrypt.Key([]byte(passphrase), nil, 32768, 8, 1, 32)
	if err != nil {
		panic(err)
	}
	if len(key) != 32 {
		panic("invalid key length after hashing")
	}
	return key
}
