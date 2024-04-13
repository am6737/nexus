package rules

import (
	"errors"
	"fmt"
	"github.com/am6737/nexus/api/interfaces"
	"github.com/am6737/nexus/config"
	"github.com/am6737/nexus/transport/packet"
	"net"
)

var _ interfaces.RulesEngine = &Rules{}

var (
	ErrDrop = errors.New("dropped packet due to rule")
)

func NewRules(outboundRules []config.OutboundRule, inboundRules []config.InboundRule, opts ...RuleOption) *Rules {
	r := &Rules{
		outbound:      outboundRules,
		inbound:       inboundRules,
		defaultAction: "deny", // 默认设置为拒绝
	}

	for _, opt := range opts {
		opt(r)
	}

	return r
}

func WithDefaultAction(action string) RuleOption {
	return func(r *Rules) {
		r.defaultAction = action
	}
}

type RuleOption func(*Rules)

type Rules struct {
	outbound []config.OutboundRule
	inbound  []config.InboundRule
	// Default action when no matching rule is found
	defaultAction string
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
			return errors.New(fmt.Sprintf("dropped packet due to rule: %v", rule))
			//return ErrDrop // Packet should be dropped
		}

		return nil // Packet should be allowed
	}

	if r.defaultAction == "deny" {
		return ErrDrop
	}
	return nil
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
			return errors.New(fmt.Sprintf("dropped packet due to rule: %v", rule))
			//return ErrDrop // Packet should be dropped
		}

		return nil // Packet should be allowed
	}

	// 根据 defaultAction 决定是否拒绝或允许
	if r.defaultAction == "deny" {
		return ErrDrop
	}
	return nil
}
