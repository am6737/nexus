package cipher

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/ProtonMail/gopenpgp/v2/helper"
	"golang.org/x/crypto/chacha20poly1305"
	"strings"
)

var chacha20poly1305Key = []byte("1234567890abcdef1234567890abcdef")

//var chacha20poly1305Key = GenerateRandomKey(chacha20poly1305.KeySize)

type NexusCipherState struct {
	p Cipher
	c Cipher

	keyPair *KeyPair
}

func (s *NexusCipherState) PublicKey() string {
	return s.keyPair.publicKey
}

func (s *NexusCipherState) PrivateKey() string {
	return s.keyPair.privateKey
}

func (s *NexusCipherState) Passphrase() string {
	return s.keyPair.passphrase
}

type SecretMessage struct {
	Message []byte `json:"message"`
	Secret  string `json:"secret"`
}

// KeyPair 结构表示一个公钥和私钥对
type KeyPair struct {
	publicKey  string
	privateKey string
	passphrase string
}

func NewNexusCipherState(name, email, passphrase string) (*NexusCipherState, error) {
	aead, err := chacha20poly1305.New(chacha20poly1305Key)
	if err != nil {
		return nil, err
	}
	c := NewChacha20poly1305Cipher(aead)

	keyPair, err := GenerateKeyPair(name, email, passphrase, 1024)
	if err != nil {
		return nil, err
	}

	return &NexusCipherState{
		p:       NewPgpCipher(),
		c:       c,
		keyPair: keyPair,
	}, nil
}

func (s *NexusCipherState) Encrypt(plaintext []byte, publicKey string) ([]byte, error) {
	// 生成一个随机 nonce 作为 ChaCha20-Poly1305 的 nonce
	nonce := GenerateRandomKey(chacha20poly1305.NonceSize)

	// 使用 ChaCha20-Poly1305 加密数据
	ciphertext, err := s.c.Encrypt(plaintext, nil, nonce)
	if err != nil {
		return nil, err
	}

	// 使用对方的公钥加密 nonce
	armoredNonce, err := helper.EncryptMessageArmored(publicKey, string(nonce))
	if err != nil {
		return nil, fmt.Errorf("无法加密 nonce: %v", err)
	}

	sm := SecretMessage{
		Message: ciphertext,
		Secret:  armoredNonce,
	}

	jsonData, err := json.Marshal(sm)
	if err != nil {
		return nil, err
	}

	return jsonData, nil
}

func (s *NexusCipherState) Decrypt(ciphertext []byte) ([]byte, error) {

	sm := SecretMessage{}

	if err := json.Unmarshal(ciphertext, &sm); err != nil {
		return nil, err
	}

	// 使用自己的私钥解密 nonce
	decryptedNonce, err := helper.DecryptBinaryMessageArmored(s.keyPair.privateKey, []byte(s.keyPair.passphrase), sm.Secret)
	if err != nil {
		return nil, err
	}

	//fmt.Println("h2解密使用的nonce => ", decryptedNonce)
	//fmt.Println("h2需要解密的密文 => ", []byte(sm.Message))

	if len(decryptedNonce) != chacha20poly1305.NonceSize {
		return nil, fmt.Errorf("nonce 长度错误")
	}

	// 使用解密后的 nonce 解密数据
	decrypted, err := s.c.Decrypt(sm.Message, nil, decryptedNonce)
	if err != nil {
		return nil, err
	}

	return decrypted, nil
}

// GenerateRandomKey 生成指定长度的随机密钥
func GenerateRandomKey(length int) []byte {
	key := make([]byte, length)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	return key
}

// GenerateKeyPair 生成 PGP 密钥对
func GenerateKeyPair(name, email, passphrase string, rsaBits int) (*KeyPair, error) {
	rsaKey, err := helper.GenerateKey(name, email, []byte(passphrase), "rsa", rsaBits)
	if err != nil {
		return nil, err
	}

	keyRing, err := crypto.NewKeyFromArmoredReader(strings.NewReader(rsaKey))
	if err != nil {
		return nil, err
	}

	publicKey, err := keyRing.GetArmoredPublicKey()
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		publicKey:  publicKey,
		privateKey: rsaKey,
		passphrase: passphrase,
	}, nil
}
