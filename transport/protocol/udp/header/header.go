package header

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	Version uint8 = 1
	Len           = 16
)

type MessageType uint8
type MessageSubType uint8

const (
	Handshake MessageType = iota
	Message
	LightHouse
	Close
	Control
)

var typeMap = map[MessageType]string{
	Handshake:  "handshake",
	Message:    "message",
	LightHouse: "lightHouse",
	Close:      "close",
	Control:    "control",
}

type Header struct {
	Version        uint8
	MessageType    MessageType
	MessageSubtype MessageSubType
	Reserved       uint16
	RemoteIndex    uint32
	MessageCounter uint64
}

// Encode 函数将提供的头部值编码到提供的字节数组中。
// 字节数组的长度必须大于等于 HeaderLen，否则会引发 panic。
func Encode(b []byte, v uint8, mt MessageType, mst MessageSubType, ri uint32, mc uint64) []byte {
	// 限制字节数组的长度为 HeaderLen
	b = b[:Len]

	// 第一个字节编码版本号和消息类型
	// 版本号占据高 4 位，消息类型占据低 4 位
	b[0] = v<<4 | byte(mt&0x0f)

	// 第二个字节编码消息子类型
	b[1] = byte(mst)

	// 接下来的两个字节是保留字段，设置为 0
	binary.BigEndian.PutUint16(b[2:4], 0)

	// 接下来的四个字节编码远程索引
	// 使用大端序编码
	binary.BigEndian.PutUint32(b[4:8], ri)

	// 接下来的八个字节编码消息计数器
	// 使用大端序编码
	binary.BigEndian.PutUint64(b[8:16], mc)

	// 返回编码后的字节数组
	return b
}

// Encode turns header into bytes
func (h *Header) Encode(b []byte) ([]byte, error) {
	if h == nil {
		return nil, errors.New("nil header")
	}

	return Encode(b, h.Version, h.MessageType, h.MessageSubtype, h.RemoteIndex, h.MessageCounter), nil
}

// Decode 将提供的字节数组解码为头部信息
func Decode(b []byte) (*Header, error) {
	if len(b) < Len {
		return nil, fmt.Errorf("byte array must be at least HeaderLen bytes long")
	}

	h := &Header{}

	// 解码第一个字节，提取版本号和消息类型
	h.Version = b[0] >> 4
	h.MessageType = MessageType(b[0] & 0x0f)

	// 解码第二个字节，提取消息子类型
	h.MessageSubtype = MessageSubType(b[1])

	// 解码保留字段，这里假设为两个字节
	h.Reserved = binary.BigEndian.Uint16(b[2:4])

	// 解码远程索引，这里假设为四个字节
	h.RemoteIndex = binary.BigEndian.Uint32(b[4:8])

	// 解码消息计数器，这里假设为八个字节
	h.MessageCounter = binary.BigEndian.Uint64(b[8:16])

	return h, nil
}
