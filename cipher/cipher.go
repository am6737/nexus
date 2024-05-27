package cipher

import (
	"crypto/cipher"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/ProtonMail/gopenpgp/v2/helper"
	"strings"
)

// GenerateKeyPair 使用个人信息生成公私钥
func GenerateKeyPair(name, email, passphrase string, rsaBits int) (string, string, error) {
	rsaKey, err := helper.GenerateKey(name, email, []byte(passphrase), "rsa", rsaBits)
	if err != nil {
		return "", "", err
	}

	keyRing, err := crypto.NewKeyFromArmoredReader(strings.NewReader(rsaKey))
	if err != nil {
		return "", "", err
	}

	publicKey, err := keyRing.GetArmoredPublicKey()
	if err != nil {
		return "", "", err
	}

	return rsaKey, publicKey, nil
}

// A Cipher is an interface for a cipher that has been initialized with a key.
type Cipher interface {
	// Encrypt encrypts the provided plaintext and appends the ciphertext to output.
	Encrypt(plaintext []byte, key []byte, nonce []byte) ([]byte, error)

	// Decrypt authenticates the ciphertext and decrypts it, appending the plaintext to output.
	Decrypt(ciphertext []byte, key []byte, nonce []byte) ([]byte, error)
}

type pgp struct {
	PublicKey  string
	PrivateKey string
	Passphrase string
}

var _ Cipher = &chacha20poly1305Cipher{}

type chacha20poly1305Cipher struct {
	c cipher.AEAD
}

func (c chacha20poly1305Cipher) Encrypt(plaintext []byte, key []byte, nonce []byte) ([]byte, error) {
	//TODO implement me
	panic("implement me")
}

func (c chacha20poly1305Cipher) Decrypt(ciphertext []byte, key []byte, nonce []byte) ([]byte, error) {
	//TODO implement me
	panic("implement me")
}

type NexusCipherState struct {
	p Cipher
	c Cipher
}

func (s *NexusCipherState) Encrypt() ([]byte, error) {
	return nil, nil
}

func (s *NexusCipherState) Decrypt() ([]byte, error) {
	return nil, nil
}
