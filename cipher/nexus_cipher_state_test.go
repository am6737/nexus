package cipher

import (
	"fmt"
	"github.com/am6737/nexus/api"
	"github.com/am6737/nexus/transport/packet"
	"github.com/am6737/nexus/transport/protocol/udp/header"
	"os"
	"testing"
)

func Test1(t *testing.T) {
	h1, err := NewNexusCipherState("h1", "h1@qq.com", "123")
	if err != nil {
		fmt.Fprintf(os.Stderr, "无法生成 PGP 密钥对: %v", err)
		os.Exit(1)
	}

	h2, err := NewNexusCipherState("h2", "h2@qq.com", "321")
	if err != nil {
		fmt.Fprintf(os.Stderr, "无法生成 PGP 密钥对: %v", err)
		os.Exit(1)
	}

	messagePacket, err := header.BuildMessage(9527, 111)
	if err != nil {
		fmt.Fprintf(os.Stderr, "无法生成消息包: %v", err)
		os.Exit(1)
	}

	var p []byte

	message := []byte("hello world")

	pk1 := (&packet.Packet{
		LocalIP:    api.Ip2VpnIp([]byte{192, 168, 1, 1}),
		RemoteIP:   api.Ip2VpnIp([]byte{192, 168, 1, 2}),
		LocalPort:  0,
		RemotePort: 0,
		Protocol:   packet.ProtoUDP,
		Fragment:   false,
	}).Encode()

	pk1 = append(pk1, message...)

	fmt.Println("加密前载荷 => ", pk1)

	ciphertext, err := h1.Encrypt(pk1, h2.keyPair.publicKey)
	if err != nil {
		panic(err)
	}

	// 创建新的数据包，将头部和数据包拼接
	p = append(messagePacket, ciphertext...)

	fmt.Println("p => ", string(p[header.Len:]))

	cleartext, err := h2.Decrypt(p[header.Len:])
	if err != nil {
		panic(err)
	}

	fmt.Println("解密前载荷 => ", cleartext)

	pk := packet.Packet{}
	if err := packet.ParsePacket(cleartext, false, &pk); err != nil {
		panic(err)
	}

	fmt.Println("pk => ", pk)

	fmt.Println("h2解密后的明文 => ", string(cleartext[20:]))
}
