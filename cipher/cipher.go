package cipher

type Cipher interface {
	Encrypt(plaintext []byte, key []byte, nonce []byte) ([]byte, error)
	Decrypt(ciphertext []byte, key []byte, nonce []byte) ([]byte, error)
}
