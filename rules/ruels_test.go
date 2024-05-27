package rules

import (
	"fmt"
	"testing"

	"github.com/am6737/nexus/api"
	"github.com/am6737/nexus/config"
	"github.com/am6737/nexus/transport/packet"
	"github.com/stretchr/testify/assert"
)

func TestMatchPort(t *testing.T) {
	tests := []struct {
		port     int
		rulePort string
		expected bool
	}{
		{80, "1-65535", true},
		{80, "22,80,443", true},
		{8080, "22,80,443", false},
		{8080, "22,80,443,8080", true},
		{100, "50-150", true},
		{200, "50-150", false},
		{80, "1-79,81-65535", false},
	}

	for _, test := range tests {
		result := matchPort(test.port, test.rulePort)
		assert.Equal(t, test.expected, result, "Port %d match rule %s: expected %v, got %v", test.port, test.rulePort, test.expected, result)
	}
}

func TestParsePortRule(t *testing.T) {
	tests := []struct {
		rule           string
		expectedPorts  []int
		expectedRanges [][2]int
		expectError    bool
	}{
		{"80,443", []int{80, 443}, nil, false},
		{"1-65535", nil, [][2]int{{1, 65535}}, false},
		{"22,80-90,100", []int{22, 100}, [][2]int{{80, 90}}, false},
		{"80-90,100-200", nil, [][2]int{{80, 90}, {100, 200}}, false},
		{"invalid", nil, nil, true},
	}

	for _, test := range tests {
		ports, ranges, err := parsePortRule(test.rule)
		if test.expectError {
			assert.Error(t, err, "Expected error for rule %s", test.rule)
		} else {
			assert.NoError(t, err, "Did not expect error for rule %s", test.rule)
			assert.Equal(t, test.expectedPorts, ports, "Expected ports %v, got %v", test.expectedPorts, ports)
			assert.Equal(t, test.expectedRanges, ranges, "Expected ranges %v, got %v", test.expectedRanges, ranges)
		}
	}
}

func TestRules_Outbound(t *testing.T) {
	rules := NewRules(
		[]config.OutboundRule{
			//{Port: "80", Proto: "tcp", Host: []string{"192.168.1.1/24"}, Action: "allow"},
			{Port: "443", Proto: "tcp", Host: []string{"192.168.1.1"}, Action: "deny"},
		},
		nil,
		WithDefaultAction("allow"), // 设置默认动作为允许
	)

	packet := &packet.Packet{
		RemotePort: 80,
		Protocol:   packet.ProtoTCP,
		RemoteIP:   api.Ip2VpnIp([]byte{192, 168, 1, 1}),
	}

	err := rules.Outbound(packet)

	fmt.Println("Packet:", packet)
	fmt.Println("Rule Applied:", rules.outbound)
	fmt.Println("Error:", err)

	assert.NoError(t, err, "Expected no error for allowed rule")

	packet.RemotePort = 443
	err = rules.Outbound(packet)

	fmt.Println("Packet:", packet)
	fmt.Println("Rule Applied:", rules.outbound)
	fmt.Println("Error:", err)

	assert.Error(t, err, "Expected error for denied rule")
	//assert.Contains(t, err.Error(), ErrDrop)
}

func TestRules_Inbound(t *testing.T) {
	rules := NewRules(
		nil,
		[]config.InboundRule{
			{Port: "80", Proto: "tcp", Host: []string{"192.168.1.1/24"}, Action: "allow"},
			{Port: "443", Proto: "tcp", Host: []string{"192.168.1.1"}, Action: "deny"},
		},
		WithDefaultAction("allow"), // 设置默认动作为允许
	)

	fmt.Println(" api.Ip2VpnIp([]byte(\"192.168.1.1\")) => ", api.Ip2VpnIp([]byte("192.168.1.1")))

	packet := &packet.Packet{
		RemotePort: 80,
		Protocol:   packet.ProtoTCP,
		RemoteIP:   api.Ip2VpnIp([]byte{192, 168, 1, 1}),
	}

	err := rules.Inbound(packet)
	assert.NoError(t, err, "Expected no error for allowed rule")

	packet.RemotePort = 443
	err = rules.Inbound(packet)
	assert.Error(t, err, "Expected error for denied rule")
	assert.Contains(t, err.Error(), ErrDrop)
}
