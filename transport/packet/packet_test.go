package packet

import (
	"github.com/am6737/nexus/api"
	"reflect"
	"testing"
)

func TestPacketEncodeDecode(t *testing.T) {
	tests := []struct {
		name string
		p    *Packet
	}{
		{
			name: "TCP packet",
			p: &Packet{
				LocalIP:    api.Ip2VpnIp([]byte{192, 168, 1, 100}),
				RemoteIP:   api.Ip2VpnIp([]byte{8, 8, 8, 8}),
				LocalPort:  0,
				RemotePort: 0,
				Protocol:   ProtoTCP,
				Fragment:   false,
			},
		},
		{
			name: "UDP packet",
			p: &Packet{
				LocalIP:    api.Ip2VpnIp([]byte{10, 0, 0, 1}),
				RemoteIP:   api.Ip2VpnIp([]byte{8, 8, 8, 8}),
				LocalPort:  0,
				RemotePort: 0,
				Protocol:   ProtoUDP,
				Fragment:   false,
			},
		},
		{
			name: "ICMP packet",
			p: &Packet{
				LocalIP:    api.Ip2VpnIp([]byte{192, 168, 0, 1}),
				RemoteIP:   api.Ip2VpnIp([]byte{8, 8, 8, 8}),
				LocalPort:  0,
				RemotePort: 0,
				Protocol:   ProtoICMP,
				Fragment:   false,
			},
		},
		{
			name: "Fragmented packet",
			p: &Packet{
				LocalIP:    api.Ip2VpnIp([]byte{172, 16, 0, 1}),
				RemoteIP:   api.Ip2VpnIp([]byte{8, 8, 8, 8}),
				LocalPort:  0,
				RemotePort: 0,
				Protocol:   ProtoTCP,
				Fragment:   false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := tt.p.Encode()
			tmp := make([]byte, 4)
			encoded = append(encoded, tmp...)
			decoded := &Packet{}
			err := decoded.Decode(encoded, false)
			if err != nil {
				t.Errorf("Decode() error = %v", err)
				return
			}

			if !reflect.DeepEqual(tt.p, decoded) {
				t.Errorf("Encode/Decode roundtrip failed:\nExpected: %+v\nGot: %+v", tt.p, decoded)
			}
		})
	}
}
