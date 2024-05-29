package cipher

import (
	"github.com/ProtonMail/gopenpgp/v2/helper"
)

var _ Cipher = &pgpCipher{}

func NewPgpCipher() Cipher {
	return &pgpCipher{}
}

type pgpCipher struct{}

func (c *pgpCipher) Encrypt(plaintext []byte, key []byte, nonce []byte) ([]byte, error) {
	ciphertext, err := helper.EncryptMessageArmored(string(key), string(plaintext))
	if err != nil {
		return nil, err
	}
	return []byte(ciphertext), nil
}

func (c *pgpCipher) Decrypt(ciphertext []byte, key []byte, nonce []byte) ([]byte, error) {
	return helper.DecryptBinaryMessageArmored(string(key), nonce, string(ciphertext))
}
