package header

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncodeDecode(t *testing.T) {
	h := &Header{
		Version:        5,
		MessageType:    4,
		MessageSubtype: 0,
		Reserved:       0,
		RemoteIndex:    10,
		MessageCounter: 9,
	}

	encoded, err := h.Encode(make([]byte, Len))
	if err != nil {
		t.Fatal("encode error:", err)
	}

	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatal("decode error:", err)
	}

	assert.Equal(t, h, decoded, "decoded header does not match original")
}

func TestEncode(t *testing.T) {
	H := &Header{
		Version:        5,
		MessageType:    4,
		MessageSubtype: 0,
		Reserved:       0,
		RemoteIndex:    10,
		MessageCounter: 9,
	}

	b, err := H.Encode(make([]byte, Len))
	if err != nil {
		t.Fatal(err)
	}

	assert.NotNil(t, b, "encoded header is nil")
	assert.Len(t, b, Len, "encoded header length is incorrect")
}

func TestDecode(t *testing.T) {
	encodedHeader := []byte{0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09}

	header, err := Decode(encodedHeader)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, Header{
		Version:        5,
		MessageType:    4,
		MessageSubtype: 0,
		Reserved:       0,
		RemoteIndex:    10,
		MessageCounter: 9,
	}, header, "decoded header does not match expected")
}
