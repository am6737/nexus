package packet

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/am6737/nexus/api"
	"golang.org/x/net/ipv4"
	"net"
)

type m map[string]interface{}

const (
	ProtoAny  = 0 // When we want to handle HOPOPT (0) we can change this, if ever
	ProtoTCP  = 6
	ProtoUDP  = 17
	ProtoICMP = 1

	PortAny      = 0  // Special value for matching `port: any`
	PortFragment = -1 // Special value for matching `port: fragment`
)

type Packet struct {
	LocalIP    api.VpnIp
	RemoteIP   api.VpnIp
	LocalPort  uint16
	RemotePort uint16
	Protocol   uint8
	Fragment   bool
}

func (p *Packet) String() string {
	return fmt.Sprintf("Packet{LocalIP: %s, RemoteIP: %s, LocalPort: %d, RemotePort: %d, Protocol: %d, Fragment: %t}",
		p.LocalIP, p.RemoteIP, p.LocalPort, p.RemotePort, p.Protocol, p.Fragment)
}

func (p *Packet) Copy() *Packet {
	return &Packet{
		LocalIP:    p.LocalIP,
		RemoteIP:   p.RemoteIP,
		LocalPort:  p.LocalPort,
		RemotePort: p.RemotePort,
		Protocol:   p.Protocol,
		Fragment:   p.Fragment,
	}
}

func (p Packet) MarshalJSON() ([]byte, error) {
	var proto string
	switch p.Protocol {
	case ProtoTCP:
		proto = "tcp"
	case ProtoICMP:
		proto = "icmp"
	case ProtoUDP:
		proto = "udp"
	default:
		proto = fmt.Sprintf("unknown %v", p.Protocol)
	}
	return json.Marshal(m{
		"LocalIP":    p.LocalIP.String(),
		"RemoteIP":   p.RemoteIP.String(),
		"LocalPort":  p.LocalPort,
		"RemotePort": p.RemotePort,
		"Protocol":   proto,
		"Fragment":   p.Fragment,
	})
}

const (
	minPacketLen = 4
)

// ParsePacket 函数用于解析数据包并返回解析后的信息
func ParsePacket(data []byte, incoming bool, p *Packet) error {
	// Do we at least have an ipv4 header worth of data?
	if len(data) < ipv4.HeaderLen {
		return fmt.Errorf("packet is less than %v bytes", ipv4.HeaderLen)
	}

	// Is it an ipv4 packet?
	if int((data[0]>>4)&0x0f) != 4 {
		return fmt.Errorf("packet is not ipv4, type: %v", int((data[0]>>4)&0x0f))
	}

	// Adjust our start position based on the advertised ip header length
	ihl := int(data[0]&0x0f) << 2

	// Well formed ip header length?
	if ihl < ipv4.HeaderLen {
		return fmt.Errorf("packet had an invalid header length: %v", ihl)
	}

	// Check if this is the second or further fragment of a fragmented packet.
	flagsfrags := binary.BigEndian.Uint16(data[6:8])
	p.Fragment = (flagsfrags & 0x1FFF) != 0

	// Firewall handles protocol checks
	p.Protocol = data[9]

	// Accounting for a variable header length, do we have enough data for our src/dst tuples?
	minLen := ihl
	if !p.Fragment && p.Protocol != ProtoICMP {
		minLen += minPacketLen
	}

	fmt.Println("len(data) => ", len(data))
	fmt.Println("minLen => ", minLen)

	if len(data) < minLen {
		return fmt.Errorf("packet is less than %v bytes, ip header len: %v", minLen, ihl)
	}

	// Firewall packets are locally oriented
	if incoming {
		p.RemoteIP = api.Ip2VpnIp(data[12:16])
		p.LocalIP = api.Ip2VpnIp(data[16:20])
		if p.Fragment || p.Protocol == ProtoICMP {
			p.RemotePort = 0
			p.LocalPort = 0
		} else {
			p.RemotePort = binary.BigEndian.Uint16(data[ihl : ihl+2])
			p.LocalPort = binary.BigEndian.Uint16(data[ihl+2 : ihl+4])
		}
	} else {
		p.LocalIP = api.Ip2VpnIp(data[12:16])
		p.RemoteIP = api.Ip2VpnIp(data[16:20])
		if p.Fragment || p.Protocol == ProtoICMP {
			p.RemotePort = 0
			p.LocalPort = 0
		} else {
			p.LocalPort = binary.BigEndian.Uint16(data[ihl : ihl+2])
			p.RemotePort = binary.BigEndian.Uint16(data[ihl+2 : ihl+4])
		}
	}

	return nil
}

// BuildIPv4Packet 构建一个符合 ParsePacket 函数逻辑的 IPv4 数据包
func BuildIPv4Packet(srcIP, dstIP net.IP, protocol uint8, isFragment bool) ([]byte, error) {
	// 创建一个 IPv4 头部
	ipHeader := make([]byte, 20)

	// 版本号和头部长度（20 字节）
	ipHeader[0] = 0x45

	// TTL 设置为 64
	ipHeader[8] = 0x40

	// 协议类型
	ipHeader[9] = protocol

	// 源 IP 和目标 IP
	copy(ipHeader[12:16], srcIP.To4())
	copy(ipHeader[16:20], dstIP.To4())

	// 如果是分片数据包，设置标志位
	if isFragment {
		ipHeader[6] |= 0x20 // 设置 DF（Don't Fragment）标志位
	}

	// 计算校验和
	checksum := calculateChecksum(ipHeader)
	binary.BigEndian.PutUint16(ipHeader[10:12], checksum)

	// 返回构建的 IPv4 数据包
	return ipHeader, nil
}

// calculateChecksum 计算 IPv4 头部的校验和
func calculateChecksum(header []byte) uint16 {
	sum := uint32(0)

	// 计算校验和时需要跳过校验和字段自身
	for i := 0; i < 10; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}

	// 跳过校验和字段
	for i := 12; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}

	// 将溢出的部分加到低位
	sum = (sum >> 16) + (sum & 0xffff)

	// 再次将溢出的部分加到低位
	sum += sum >> 16

	// 取反得到校验和
	return uint16(^sum)
}
