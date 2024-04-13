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

var protocolMap = map[uint8]string{
	ProtoTCP:  "tcp",
	ProtoUDP:  "udp",
	ProtoICMP: "icmp",
}

func TypeName(t uint8) string {
	if n, ok := protocolMap[t]; ok {
		return n
	}

	return "unknown"
}

type Packet struct {
	LocalIP    api.VpnIP
	RemoteIP   api.VpnIP
	LocalPort  uint16
	RemotePort uint16
	Protocol   uint8
	Fragment   bool
}

func (p *Packet) String() string {
	fragment := "no"
	if p.Fragment {
		fragment = "yes"
	}
	return fmt.Sprintf("LocalIP=%s RemoteIP=%s LocalPort=%d RemotePort=%d Protocol=%s Fragment=%v",
		p.LocalIP, p.RemoteIP, p.LocalPort, p.RemotePort, TypeName(p.Protocol), fragment)
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
// incoming true 时表示数据包是从conn流入tun，false 表示数据包从tun流出
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

func (p *Packet) Encode() []byte {
	data := make([]byte, 20)
	// IPv4 header format:
	// 0-3 bits: Version
	// 4-7 bits: IHL (IP Header Length)
	// 8-15 bits: Type of Service
	// 16-31 bits: Total Length
	// 32-47 bits: Identification
	// 48-51 bits: Flags
	// 52-63 bits: Fragment Offset
	// 64-71 bits: Time to Live
	// 72-79 bits: Protocol
	// 80-111 bits: Header Checksum
	// 112-143 bits: Source IP Address
	// 144-175 bits: Destination IP Address
	// 176-207 bits: Options (if any)

	//data[0] = 0x45                            // Version 4, IHL 5
	//binary.BigEndian.PutUint16(data[2:4], 20) // Total Length
	//data[9] = p.Protocol
	//copy(data[12:16], p.LocalIP.ToIP())
	//copy(data[16:20], p.RemoteIP.ToIP())
	//binary.BigEndian.PutUint16(data[0:2], uint16(len(data))) // Total Length
	//if p.Fragment {
	//	data[6] |= 0x20 // Set the More Fragments flag
	//}

	// 创建一个 IPv4 头部
	ipHeader := make([]byte, 20)
	// 版本号和头部长度（20 字节）
	ipHeader[0] = 0x45
	//binary.BigEndian.PutUint16(data[2:4], 20) // Total Length
	// TTL 设置为 64
	ipHeader[8] = 0x40
	// 协议类型
	ipHeader[9] = p.Protocol
	// 源 IP 和目标 IP
	copy(ipHeader[12:16], p.LocalIP.ToIP())
	copy(ipHeader[16:20], p.RemoteIP.ToIP())

	// 如果是分片数据包，设置标志位
	if p.Fragment {
		ipHeader[6] |= 0x20 // 设置 DF（Don't Fragment）标志位
	}
	checksum := calculateChecksum(ipHeader)
	binary.BigEndian.PutUint16(ipHeader[10:12], checksum)
	return data
}

func (p *Packet) Decode(data []byte) error {
	if len(data) < 20 {
		return fmt.Errorf("packet data is less than 20 bytes")
	}

	// Check if it's an IPv4 packet
	if (data[0] >> 4) != 4 {
		return fmt.Errorf("packet is not IPv4")
	}

	// Extract the IP header length
	ihl := int(data[0]&0x0F) * 4

	// Extract the protocol
	p.Protocol = data[9]

	// Extract the source and destination IP addresses
	p.LocalIP = api.Ip2VpnIp(data[12:16])
	p.RemoteIP = api.Ip2VpnIp(data[16:20])

	// Extract the source and destination ports
	if ihl >= 20 && (p.Protocol == ProtoTCP || p.Protocol == ProtoUDP) {
		p.LocalPort = binary.BigEndian.Uint16(data[ihl : ihl+2])
		p.RemotePort = binary.BigEndian.Uint16(data[ihl+2 : ihl+4])
	} else {
		p.LocalPort = 0
		p.RemotePort = 0
	}

	// Check if the packet is fragmented
	flags := binary.BigEndian.Uint16(data[6:8])
	p.Fragment = (flags & 0x1FFF) != 0

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
