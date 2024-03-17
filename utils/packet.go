package utils

import (
	"encoding/binary"
	"fmt"
	"github.com/am6737/nexus/api"
	"github.com/am6737/nexus/transport/packet"
	"golang.org/x/net/ipv4"
)

const (
	minPacketLen = 4
)

// ParsePacket 函数用于解析数据包并返回解析后的信息
func ParsePacket(data []byte, incoming bool, p *packet.Packet) error {
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
	if !p.Fragment && p.Protocol != packet.ProtoICMP {
		minLen += minPacketLen
	}
	if len(data) < minLen {
		return fmt.Errorf("packet is less than %v bytes, ip header len: %v", minLen, ihl)
	}

	// Firewall packets are locally oriented
	if incoming {
		p.RemoteIP = api.Ip2VpnIp(data[12:16])
		p.LocalIP = api.Ip2VpnIp(data[16:20])
		if p.Fragment || p.Protocol == packet.ProtoICMP {
			p.RemotePort = 0
			p.LocalPort = 0
		} else {
			p.RemotePort = binary.BigEndian.Uint16(data[ihl : ihl+2])
			p.LocalPort = binary.BigEndian.Uint16(data[ihl+2 : ihl+4])
		}
	} else {
		p.LocalIP = api.Ip2VpnIp(data[12:16])
		p.RemoteIP = api.Ip2VpnIp(data[16:20])
		if p.Fragment || p.Protocol == packet.ProtoICMP {
			p.RemotePort = 0
			p.LocalPort = 0
		} else {
			p.LocalPort = binary.BigEndian.Uint16(data[ihl : ihl+2])
			p.RemotePort = binary.BigEndian.Uint16(data[ihl+2 : ihl+4])
		}
	}

	return nil
}
