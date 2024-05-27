package main

import (
	"crypto/rand"
	"fmt"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/ProtonMail/gopenpgp/v2/helper"
	"golang.org/x/crypto/chacha20poly1305"
	"os"
	"strings"
)

// Cipher 接口定义了加密和解密的方法
type Cipher interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

// ChaCha20Poly1305 实现了 Cipher 接口
type ChaCha20Poly1305 struct {
	Key []byte
}

// NewChaCha20Poly1305 创建一个新的 ChaCha20Poly1305 实例
func NewChaCha20Poly1305(key []byte) *ChaCha20Poly1305 {
	return &ChaCha20Poly1305{
		Key: key,
	}
}

// Encrypt 使用 ChaCha20Poly1305 加密数据
func (c *ChaCha20Poly1305) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.New(c.Key)
	if err != nil {
		return nil, err
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

// Decrypt 使用 ChaCha20Poly1305 解密数据
func (c *ChaCha20Poly1305) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < chacha20poly1305.NonceSize {
		return nil, fmt.Errorf("invalid ciphertext")
	}

	nonce := ciphertext[:chacha20poly1305.NonceSize]
	ciphertext = ciphertext[chacha20poly1305.NonceSize:]

	aead, err := chacha20poly1305.New(c.Key)
	if err != nil {
		return nil, err
	}

	return aead.Open(nil, nonce, ciphertext, nil)
}

// PGP 实现了 Cipher 接口
type PGP struct {
	PublicKey  string
	PrivateKey string
	Passphrase string
}

// NewPGP 创建一个新的 PGP 实例
func NewPGP(publicKey, privateKey, passphrase string) *PGP {
	return &PGP{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
		Passphrase: passphrase,
	}
}

// Encrypt 使用 PGP 加密数据
func (p *PGP) Encrypt(plaintext []byte) ([]byte, error) {
	password, err := helper.EncryptMessageWithPassword(plaintext, p.Passphrase)
	if err != nil {
		return nil, err
	}
	return []byte(password), nil
}

// Decrypt 使用 PGP 解密数据
func (p *PGP) Decrypt(ciphertext []byte) ([]byte, error) {
	password, err := helper.DecryptMessageWithPassword([]byte(p.PrivateKey), string(ciphertext))
	if err != nil {
		return nil, err
	}
	return []byte(password), nil
}

// KeyPair 结构表示一个公钥和私钥对
type KeyPair struct {
	PublicKey  string
	PrivateKey string
	Passphrase string
}

// Message 结构表示加密的消息和相关信息
type Message struct {
	Ciphertext []byte
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
		PublicKey:  publicKey,
		PrivateKey: rsaKey,
		Passphrase: passphrase,
	}, nil
}

// Host1 模拟主机1的操作
func Host1(h1, h2 *KeyPair, cipher Cipher) *Message {
	// 使用 Cipher 加密数据
	ciphertext, err := cipher.Encrypt([]byte(message))
	if err != nil {
		fmt.Fprintf(os.Stderr, "加密失败: %v", err)
		os.Exit(1)
	}

	return &Message{
		Ciphertext: ciphertext,
	}
}

// Host2 模拟主机2的操作
func Host2(h2 *KeyPair, message *Message, cipher Cipher) {
	// 使用 Cipher 解密数据
	plaintext, err := cipher.Decrypt(message.Ciphertext)
	if err != nil {
		fmt.Fprintf(os.Stderr, "解密失败: %v", err)
		os.Exit(1)
	}

	fmt.Printf("解密后的明文: %s\n", plaintext)
}

var (
	message = "Hello World"
)

func main() {
	// 生成 ChaCha20Poly1305 密钥
	chachaKey := GenerateRandomKey(chacha20poly1305.KeySize)
	fmt.Printf("ChaCha20Poly1305 密钥: %x\n", chachaKey)

	h1, err := GenerateKeyPair("h1", "h1@qq.com", "123", 1024)
	if err != nil {
		fmt.Fprintf(os.Stderr, "无法生成 PGP 密钥对: %v", err)
		os.Exit(1)
	}

	h2, err := GenerateKeyPair("h2", "h2@qq.com", "321", 1024)
	if err != nil {
		fmt.Fprintf(os.Stderr, "无法生成 PGP 密钥对: %v", err)
		os.Exit(1)
	}

	cipher := NewChaCha20Poly1305(chachaKey)
	msg := Host1(h1, h2, cipher)
	Host2(h2, msg, cipher)
}
