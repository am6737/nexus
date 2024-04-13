package interfaces

import "github.com/am6737/nexus/transport/packet"

// RulesEngine is an interface that defines the behavior of a rules engine
// for handling inbound and outbound network packets.
type RulesEngine interface {
	// Outbound processes an outbound network packet and returns an error
	// if the packet should be dropped based on the configured rules.
	// If the packet is allowed, the method returns nil.
	Outbound(*packet.Packet) error

	// Inbound processes an inbound network packet and returns an error
	// if the packet should be dropped based on the configured rules.
	// If the packet is allowed, the method returns nil.
	Inbound(*packet.Packet) error
}
