package cipher

import (
	"crypto/cipher"
)

var _ Cipher = &chacha20poly1305Cipher{}

func NewChacha20poly1305Cipher(c cipher.AEAD) Cipher {
	return &chacha20poly1305Cipher{
		c: c,
	}
}

type chacha20poly1305Cipher struct {
	c cipher.AEAD
}

func (c *chacha20poly1305Cipher) Encrypt(plaintext []byte, key []byte, nonce []byte) ([]byte, error) {
	ciphertext := c.c.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nil
}

func (c *chacha20poly1305Cipher) Decrypt(ciphertext []byte, key []byte, nonce []byte) ([]byte, error) {
	return c.c.Open(nil, nonce, ciphertext, nil)
}
