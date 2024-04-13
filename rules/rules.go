package rules

import (
	"errors"
	"github.com/am6737/nexus/api/interfaces"
	"github.com/am6737/nexus/config"
	"github.com/am6737/nexus/transport/packet"
	"net"
)

var _ interfaces.RulesEngine = &Rules{}

var (
	ErrDrop = errors.New("dropped packet due to rule")
)

func NewRules(outboundRules []config.OutboundRule, inboundRules []config.InboundRule) *Rules {
	return &Rules{
		outbound: outboundRules,
		inbound:  inboundRules,
	}
}

type Rules struct {
	outbound []config.OutboundRule
	inbound  []config.InboundRule
}

func (r *Rules) Outbound(p *packet.Packet) error {
	for _, rule := range r.outbound {
		if rule.Proto != "any" && rule.Proto != packet.TypeName(p.Protocol) {
			continue // Protocol doesn't match
		}

		if rule.Port != config.AnyPortValue && rule.Port.ToUint16() != p.RemotePort {
			continue // Port doesn't match
		}

		matched := false
		if len(rule.Host) > 0 {
			for _, host := range rule.Host {
				_, network, err := net.ParseCIDR(host)
				if err == nil && network.Contains(p.RemoteIP.ToNetIP()) {
					matched = true
					break
				} else if host == p.RemoteIP.String() {
					matched = true
					break
				}
			}
		} else {
			matched = true
		}
		if !matched {
			continue // Host doesn't match
		}

		if rule.Action == "deny" {
			return ErrDrop // Packet should be dropped
		}

		return nil // Packet should be allowed
	}

	return nil // No matching outbound rule found
}

func (r *Rules) Inbound(p *packet.Packet) error {
	for _, rule := range r.inbound {
		if rule.Proto != "any" && rule.Proto != packet.TypeName(p.Protocol) {
			continue // Protocol doesn't match
		}

		if rule.Port != config.AnyPortValue && rule.Port.ToUint16() != p.RemotePort {
			continue // Port doesn't match
		}

		matched := false
		if len(rule.Host) > 0 {
			for _, host := range rule.Host {
				_, network, err := net.ParseCIDR(host)
				if err == nil && network.Contains(p.RemoteIP.ToNetIP()) {
					matched = true
					break
				} else if host == p.RemoteIP.String() {
					matched = true
					break
				}
			}
		} else {
			matched = true
		}
		if !matched {
			continue // Host doesn't match
		}

		if rule.Action == "deny" {
			return ErrDrop // Packet should be dropped
		}

		return nil // Packet should be allowed
	}

	return nil // No matching inbound rule found
}
