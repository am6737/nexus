package udp

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
)

// Packet 包含UDP数据包的结构定义
type Packet struct {
	SourcePort      uint16
	DestinationPort uint16
	Length          uint16
	Checksum        uint16
	Payload         []byte
}

// Copy 方法用于复制整个UDP数据包
func (udp *Packet) Copy() *Packet {
	copiedData := make([]byte, len(udp.Payload))
	copy(copiedData, udp.Payload)
	return &Packet{
		SourcePort:      udp.SourcePort,
		DestinationPort: udp.DestinationPort,
		Length:          udp.Length,
		Checksum:        udp.Checksum,
		Payload:         copiedData,
	}
}

// MarshalJSON 方法用于将UDP数据包转换为JSON格式
func (udp *Packet) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		SourcePort      uint16 `json:"source_port"`
		DestinationPort uint16 `json:"destination_port"`
		Length          uint16 `json:"length"`
		Checksum        uint16 `json:"checksum"`
		Payload         []byte `json:"payload"`
	}{
		SourcePort:      udp.SourcePort,
		DestinationPort: udp.DestinationPort,
		Length:          udp.Length,
		Checksum:        udp.Checksum,
		Payload:         udp.Payload,
	})
}

// Serialize 将UDP数据包序列化为字节流
func (udp *Packet) Serialize() []byte {
	packet := make([]byte, 8+len(udp.Payload))
	binary.BigEndian.PutUint16(packet[0:2], udp.SourcePort)
	binary.BigEndian.PutUint16(packet[2:4], udp.DestinationPort)
	binary.BigEndian.PutUint16(packet[4:6], udp.Length)
	binary.BigEndian.PutUint16(packet[6:8], udp.Checksum)
	copy(packet[8:], udp.Payload)
	return packet
}

// Deserialize 从字节流反序列化为UDP数据包
func (udp *Packet) Unmarshal(data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("invalid UDP packet: insufficient length")
	}
	udp.SourcePort = binary.BigEndian.Uint16(data[0:2])
	udp.DestinationPort = binary.BigEndian.Uint16(data[2:4])
	udp.Length = binary.BigEndian.Uint16(data[4:6])
	udp.Checksum = binary.BigEndian.Uint16(data[6:8])
	udp.Payload = data[8:]
	return nil
}

// CalculateChecksum 计算UDP数据包的校验和
func (udp *Packet) CalculateChecksum() uint16 {
	sum := uint32(0)

	// 计算伪首部校验和
	pseudoHeader := []uint16{
		udp.SourcePort, udp.DestinationPort,
		udp.Length,
	}
	for _, value := range pseudoHeader {
		sum += uint32(value)
	}

	// 计算数据部分校验和
	for i := 0; i < len(udp.Payload)-1; i += 2 {
		sum += uint32(udp.Payload[i])<<8 + uint32(udp.Payload[i+1])
	}

	// 如果数据部分长度为奇数，处理最后一个字节
	if len(udp.Payload)%2 != 0 {
		sum += uint32(udp.Payload[len(udp.Payload)-1]) << 8
	}

	// 将进位加到低16位
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	// 取反得到校验和
	checksum := uint16(^sum)
	return checksum
}

// ValidateChecksum 验证UDP数据包的校验和
func (udp *Packet) ValidateChecksum() bool {
	return udp.Checksum == udp.CalculateChecksum()
}
