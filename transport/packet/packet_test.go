package packet

import (
	"encoding/binary"
	"fmt"
	"golang.org/x/net/ipv4"
	"net"
	"reflect"
	"testing"
)

func Test_newPacket(t *testing.T) {
	p := &Packet{}

	h := ipv4.Header{
		Version:  1,
		Len:      20,
		Src:      net.IPv4(10, 0, 0, 1),
		Dst:      net.IPv4(10, 0, 0, 2),
		Options:  []byte{0, 1, 0, 2},
		Protocol: ProtoUDP,
	}

	//localPort := uint16(8080)
	//remotePort := uint16(8081)
	//
	b, _ := h.Marshal()

	fmt.Println("len 1 => ", len(b))
	//
	//// 将本地端口号添加到数据包中（大端字节序）
	//localPortBytes := make([]byte, 2)
	//binary.BigEndian.PutUint16(localPortBytes, localPort)
	//b = append(b, localPortBytes...)
	//
	//// 将远程端口号添加到数据包中（大端字节序）
	//remotePortBytes := make([]byte, 2)
	//binary.BigEndian.PutUint16(remotePortBytes, remotePort)
	//b = append(b, remotePortBytes...)

	b = append(b, []byte{0, 3, 0, 4}...)
	fmt.Println("len(b) => ", len(b))
	err := ParsePacket(b, false, p)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("b => ", b)

	json, err := p.MarshalJSON()
	if err != nil {
		return
	}
	fmt.Println("p => ", string(json))
}

func TestBuildIPv4Packet(t *testing.T) {
	srcIP := net.ParseIP("192.168.1.1")
	dstIP := net.ParseIP("192.168.2.2")
	protocol := ProtoTCP
	isFragment := false

	packet, err := BuildIPv4Packet(srcIP, dstIP, uint8(protocol), isFragment)
	if err != nil {
		t.Errorf("Error building IPv4 packet: %v", err)
	}

	// 添加足够的数据以确保数据包长度达到预期值
	additionalData := make([]byte, 4) // 4 字节的额外数据
	packet = append(packet, additionalData...)

	p := &Packet{}
	err = ParsePacket(packet, false, p)
	if err != nil {
		panic(err)
	}

	fmt.Println("packet => ", packet)

	fmt.Println("p => ", p)

	// 检查头部长度
	if len(packet) < ipv4.HeaderLen {
		t.Errorf("Expected IPv4 packet length %d, got %d", ipv4.HeaderLen, len(packet))
	}

	// 检查版本号和头部长度字段
	if packet[0] != 0x45 {
		t.Errorf("Expected version and header length 0x45, got 0x%x", packet[0])
	}

	// 检查 TTL 字段
	if packet[8] != 0x40 {
		t.Errorf("Expected TTL 0x40, got 0x%x", packet[8])
	}

	// 检查协议类型字段
	if packet[9] != uint8(protocol) {
		t.Errorf("Expected protocol %d, got %d", protocol, packet[9])
	}

	// 检查源 IP 和目标 IP 字段
	if !reflect.DeepEqual(packet[12:16], srcIP.To4()) {
		t.Errorf("Expected source IP %v, got %v", srcIP.To4(), packet[12:16])
	}
	if !reflect.DeepEqual(packet[16:20], dstIP.To4()) {
		t.Errorf("Expected destination IP %v, got %v", dstIP.To4(), packet[16:20])
	}

	// 检查标志位字段
	if packet[6]&0x20 != 0 && isFragment {
		t.Errorf("Expected DF flag to be set, but it is not")
	} else if packet[6]&0x20 == 0 && !isFragment {
		t.Errorf("Expected DF flag not to be set, but it is")
	}

	// 在此添加更多的字段验证...

	// 检查校验和字段
	calculatedChecksum := calculateChecksum(packet)
	expectedChecksum := binary.BigEndian.Uint16(packet[10:12])
	if calculatedChecksum != expectedChecksum {
		t.Errorf("Expected checksum %d, got %d", expectedChecksum, calculatedChecksum)
	}
}
