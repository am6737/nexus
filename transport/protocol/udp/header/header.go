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
	Handshake MessageType = iota + 1
	Message
	LightHouse
	Close
	Control
	Test
)

const (
	TestRequest MessageSubType = 0
	TestReply   MessageSubType = 1
)

const (
	HostQuery MessageSubType = iota + 1
	HostQueryReply
	HostUpdateNotification
	HostSync
	HostSyncReply
	HostPunch
	HostPunchReply
	HostHandshakeRequest
	HostHandshakeReply
)

var subtTypeMap = map[MessageSubType]string{
	HostQuery:              "hostQuery",
	HostQueryReply:         "hostQueryReply",
	HostUpdateNotification: "hostUpdateNotification",
	HostSync:               "hostSync",
	HostSyncReply:          "hostSyncReply",
	HostPunch:              "hostPunch",
	HostPunchReply:         "hostPunchReply",
	HostHandshakeRequest:   "hostHandshakeRequest",
	HostHandshakeReply:     "hostHandshakeReply",
}

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

func BuildTest(ms MessageType, remoteIndex uint32, messageCounter uint64) []byte {
	return buildPacket(ms, 0, remoteIndex, messageCounter)
}

func BuildHostQueryReply(remoteIndex uint32, messageCounter uint64) []byte {
	return buildPacket(LightHouse, HostQueryReply, remoteIndex, messageCounter)
}

func BuildMessage(remoteIndex uint32, messageCounter uint64) ([]byte, error) {
	return buildPacket(Message, 0, remoteIndex, messageCounter), nil
}

func BuildHandshake(remoteIndex uint32, ms MessageSubType, messageCounter uint64) ([]byte, error) {
	return buildPacket(Handshake, ms, remoteIndex, messageCounter), nil
}

func BuildHandshakeAndHostSync(remoteIndex uint32, messageCounter uint64) ([]byte, error) {
	return buildPacket(Handshake, HostSync, remoteIndex, messageCounter), nil
}

func BuildHandshakeAndHostPunch(remoteIndex uint32, messageCounter uint64) ([]byte, error) {
	return buildPacket(Handshake, HostPunch, remoteIndex, messageCounter), nil
}

func BuildHandshakeAndHostReply(remoteIndex uint32, messageCounter uint64) []byte {
	return buildPacket(Handshake, HostHandshakeReply, remoteIndex, messageCounter)
}

func buildPacket(mt MessageType, mst MessageSubType, remoteIndex uint32, messageCounter uint64) []byte {
	header := &Header{
		Version:        Version,
		MessageType:    mt,
		MessageSubtype: mst,
		Reserved:       0,
		RemoteIndex:    remoteIndex,
		MessageCounter: messageCounter,
	}

	packet := make([]byte, Len)
	encodedHeader, _ := header.Encode(packet)
	return encodedHeader
}

func (h *Header) Encode(b []byte) ([]byte, error) {
	if h == nil {
		return nil, errors.New("nil header")
	}

	return Encode(b, h.Version, h.MessageType, h.MessageSubtype, h.RemoteIndex, h.MessageCounter), nil
}

func Encode(b []byte, v uint8, mt MessageType, mst MessageSubType, ri uint32, mc uint64) []byte {
	b = b[:Len]
	b[0] = v<<4 | byte(mt&0x0f)
	b[1] = byte(mst)
	binary.BigEndian.PutUint16(b[2:4], 0)
	binary.BigEndian.PutUint32(b[4:8], ri)
	binary.BigEndian.PutUint64(b[8:16], mc)
	return b
}

func (h *Header) Decode(b []byte) error {
	if len(b) < Len {
		return fmt.Errorf("byte array must be at least HeaderLen bytes long")
	}

	h.Version = b[0] >> 4
	h.MessageType = MessageType(b[0] & 0x0f)
	h.MessageSubtype = MessageSubType(b[1])
	h.Reserved = binary.BigEndian.Uint16(b[2:4])
	h.RemoteIndex = binary.BigEndian.Uint32(b[4:8])
	h.MessageCounter = binary.BigEndian.Uint64(b[8:16])

	return nil
}

func (h *Header) String() string {
	if h == nil {
		return "<nil>"
	}
	return fmt.Sprintf("version=%d messagetype=%s subtype=%s reserved=%#x remoteindex=%v messagecounter=%v",
		h.Version, h.TypeName(), h.SubTypeName(), h.Reserved, h.RemoteIndex, h.MessageCounter)
}

func (h *Header) TypeName() string {
	return TypeName(h.MessageType)
}

func TypeName(t MessageType) string {
	if n, ok := typeMap[t]; ok {
		return n
	}
	return "unknown"
}

func (h *Header) SubTypeName() string {
	return SubTypeName(h.MessageSubtype)
}

func SubTypeName(s MessageSubType) string {
	if n, ok := subtTypeMap[s]; ok {
		return n
	}
	return "unknown"
}
