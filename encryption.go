package secutil

// IEncryption describes the interface for an encryption implementation
type IEncryption interface {
	Encrypt(data []byte, passphrase string) ([]byte, error)
	EncryptKey(data []byte, key []byte) ([]byte, error)
	Decrypt(data []byte, passphrase string) ([]byte, error)
	DecryptKey(data []byte, key []byte) ([]byte, error)
	PassphraseToKey(passphrase string) []byte
}

// EncryptionAES256GCM is an implementation of the IEncryption interface for AES-256-GCM cryptography
type EncryptionAES256GCM struct{}

// EncryptionChaCha20Poly1305 is an implementation of the IEncryption interface for ChaCha20-Poly1305 cryptography
type EncryptionChaCha20Poly1305 struct{}

// Encryption provides access to a standard interface for cryptographic encryption and decrption tasks
var Encryption = struct {
	AES_256_GCM       IEncryption
	CHACHA20_POLY1305 IEncryption
}{
	AES_256_GCM:       EncryptionAES256GCM{},
	CHACHA20_POLY1305: EncryptionChaCha20Poly1305{},
}
