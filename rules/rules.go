package rules

import (
	"fmt"
	"github.com/am6737/nexus/api/interfaces"
	"github.com/am6737/nexus/config"
	"github.com/am6737/nexus/transport/packet"
	"net"
	"strconv"
	"strings"
)

var _ interfaces.RulesEngine = &Rules{}

var (
	AnyPort        = "1-65535"
	ErrDrop        = "dropped packet due to rule"
	defaultErrDrop = "default action is deny"
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

		if rule.Port != "any" && rule.Port != AnyPort && !matchPort(int(p.RemotePort), rule.Port) {
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
			matched = false
		}
		if !matched {
			continue // Host doesn't match
		}

		if rule.Action == "deny" {
			return fmt.Errorf("%s: %v", ErrDrop, rule)
		}

		return nil // Packet should be allowed
	}

	if r.defaultAction == "deny" {
		return fmt.Errorf("%s: %v", ErrDrop, defaultErrDrop)
	}
	return nil
}

func (r *Rules) Inbound(p *packet.Packet) error {
	for _, rule := range r.inbound {
		if rule.Proto != "any" && rule.Proto != packet.TypeName(p.Protocol) {
			continue // Protocol doesn't match
		}

		if rule.Port != "any" && rule.Port != AnyPort && !matchPort(int(p.RemotePort), rule.Port) {
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
			matched = false
		}
		if !matched {
			continue // Host doesn't match
		}

		if rule.Action == "deny" {
			return fmt.Errorf("%s: %v", ErrDrop, rule)
		}

		return nil // Packet should be allowed
	}

	// 根据 defaultAction 决定是否拒绝或允许
	if r.defaultAction == "deny" {
		return fmt.Errorf("%s: %v", ErrDrop, defaultErrDrop)
	}
	return nil
}

func parsePortRule(rule string) ([]int, [][2]int, error) {
	var ports []int
	var ranges [][2]int
	parts := strings.Split(rule, ",")
	for _, part := range parts {
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, nil, fmt.Errorf("invalid port range format: %s", part)
			}
			start, err := strconv.Atoi(rangeParts[0])
			if err != nil {
				return nil, nil, err
			}
			end, err := strconv.Atoi(rangeParts[1])
			if err != nil {
				return nil, nil, err
			}
			if start > end {
				return nil, nil, fmt.Errorf("start port greater than end port: %s", part)
			}
			ranges = append(ranges, [2]int{start, end})
		} else {
			port, err := strconv.Atoi(part)
			if err != nil {
				return nil, nil, err
			}
			ports = append(ports, port)
		}
	}
	return ports, ranges, nil
}

func portInRanges(port int, ranges [][2]int) bool {
	for _, r := range ranges {
		if port >= r[0] && port <= r[1] {
			return true
		}
	}
	return false
}

func (r *Rules) matchPort(rulePort string, packetPort int) (bool, error) {
	ports, ranges, err := parsePortRule(rulePort)
	if err != nil {
		return false, err
	}

	for _, port := range ports {
		if packetPort == port {
			return true, nil
		}
	}

	if portInRanges(packetPort, ranges) {
		return true, nil
	}

	return false, nil
}

// matchPort 检查给定的端口是否符合规则字符串中的任意规则。
func matchPort(port int, rulePort string) bool {
	// 规则字符串可以是单个端口，逗号分隔的端口列表，或者范围
	rules := strings.Split(rulePort, ",")
	for _, r := range rules {
		if strings.Contains(r, "-") {
			// 处理范围
			bounds := strings.Split(r, "-")
			if len(bounds) != 2 {
				continue
			}
			lower, err1 := strconv.Atoi(bounds[0])
			upper, err2 := strconv.Atoi(bounds[1])
			if err1 != nil || err2 != nil {
				continue
			}
			if port >= lower && port <= upper {
				return true
			}
		} else {
			// 处理单个端口
			p, err := strconv.Atoi(r)
			if err != nil {
				continue
			}
			if port == p {
				return true
			}
		}
	}
	return false
}
