package secutil_test

import (
	"encoding/hex"
	"fmt"

	"github.com/ecnepsnai/secutil"
)

func ExampleEncryptionAES256GCM_Encrypt() {
	passphrase := "password"
	data := []byte("some secret data")

	encryptedBytes, err := secutil.Encryption.AES_256_GCM.Encrypt(data, passphrase)
	if err != nil {
		panic(err)
	}

	// Encrypted bytes are binary so you may wish to encode them as hex bytes
	hexBytes := hex.EncodeToString(encryptedBytes)

	fmt.Printf("Encrypted bytes: %s\n", hexBytes)
}

func ExampleEncryptionAES256GCM_Decrypt() {
	encryptedBytes, _ := hex.DecodeString("4cf3c191dc75cdbd37bca050c99028ef8b43cbb85b36a890ea5ad074eaa1a250e62dad0a3da0cd090a08cfd1")
	passphrase := "password"

	decryptedBytes, err := secutil.Encryption.AES_256_GCM.Decrypt(encryptedBytes, passphrase)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%s\n", decryptedBytes)
	// output: some secret data
}

func ExampleEncryptionChaCha20Poly1305_Encrypt() {
	passphrase := "password"
	data := []byte("some secret data")

	encryptedBytes, err := secutil.Encryption.CHACHA20_POLY1305.Encrypt(data, passphrase)
	if err != nil {
		panic(err)
	}

	// Encrypted bytes are binary so you may wish to encode them as hex bytes
	hexBytes := hex.EncodeToString(encryptedBytes)

	fmt.Printf("Encrypted bytes: %s\n", hexBytes)
}

func ExampleEncryptionChaCha20Poly1305_Decrypt() {
	encryptedBytes, _ := hex.DecodeString("c2b602e819dbac10ac1cf9f3b9408c783b1769a703bc2169131046af4715fd70005228fb00c894d3a6d0877ab637261d593b28888600bf5d")
	passphrase := "password"

	decryptedBytes, err := secutil.Encryption.CHACHA20_POLY1305.Decrypt(encryptedBytes, passphrase)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%s\n", decryptedBytes)
	// output: some secret data
}
