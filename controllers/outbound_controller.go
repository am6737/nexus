package controllers

import (
	"context"
	"errors"
	"github.com/am6737/nexus/api"
	"github.com/am6737/nexus/api/interfaces"
	"github.com/am6737/nexus/config"
	"github.com/am6737/nexus/ifce"
	"github.com/am6737/nexus/transport/packet"
	"github.com/am6737/nexus/tun"
	"github.com/am6737/nexus/utils"
	"github.com/sirupsen/logrus"
	"io"
	"net"
	"os"
	"runtime"
	"sync/atomic"
)

const (
	mtu = 9001
)

var _ interfaces.OutboundController = &OutboundController{}

// OutboundController 出站控制器 必须实现 interfaces.OutboundController 接口
type OutboundController struct {
	mtu        int
	closed     atomic.Bool
	localVpnIP api.VpnIP
	inside     tun.Device
	logger     *logrus.Logger
	cfg        *config.Config
	rules      interfaces.RulesEngine
}

func (ic *OutboundController) Start(ctx context.Context) error {
	if err := ic.inside.Up(); err != nil {
		if err := ic.inside.Close(); err != nil {
			ic.logger.WithError(err).Error("Failed to up tun device")
		}
		ic.logger.Fatal(err)
	}
	ic.logger.
		WithField("localVpnIP", ic.localVpnIP).
		WithField("dev", ic.cfg.Tun.Dev).
		WithField("mtu", ic.mtu).
		Info("Starting inbound controller")
	return nil
}

func (ic *OutboundController) Send(p []byte) (n int, err error) {
	return ic.inside.Write(p)
}

func (ic *OutboundController) Listen(externalWriter interfaces.OutsideWriter) {
	runtime.LockOSThread()
	p := &packet.Packet{}
	packet := make([]byte, mtu)
	for {
		n, err := ic.inside.Read(packet)
		if err != nil {
			if errors.Is(err, os.ErrClosed) && ic.closed.Load() {
				return
			}
			ic.logger.WithError(err).Error("Error while reading outbound packet")
			// This only seems to happen when something fatal happens to the fd, so exit.
			os.Exit(2)
		}
		ic.consumeInsidePacket(packet[:n], p, ic.inside, externalWriter)
	}
}

func (ic *OutboundController) consumeInsidePacket(data []byte, packet *packet.Packet, internalWriter io.Writer, externalWriter interfaces.OutsideWriter) {
	if err := utils.ParsePacket(data, false, packet); err != nil {
		//ic.logger.WithField("packet", packet).Debugf("consumeInsidePacket Error while validating outbound packet: %s", err)
		return
	}

	if packet.RemoteIP == ic.localVpnIP {
		if ifce.ImmediatelyForwardToSelf {
			if _, err := internalWriter.Write(data); err != nil {
				ic.logger.WithError(err).Error("Failed to forward to tun")
			}
		}
		return
	}

	// Check the rules
	if err := ic.rules.Outbound(packet); err != nil {
		ic.logger.WithError(err).Warn("Dropped packet due to rule")
		return
	}

	if err := externalWriter.WriteToVIP(data, packet.RemoteIP); err != nil {
		ic.logger.WithError(err).Error("Error while forwarding outbound packet")
		return
	}
}

func (ic *OutboundController) checkRules(p *packet.Packet) string {
	// Implement the logic to check the rules and return the appropriate action
	for _, rule := range ic.cfg.Inbound {
		//fmt.Println("rule.Proto => ", rule.Proto)
		//fmt.Println("packet.TypeName(p.Protocol)  => ", packet.TypeName(p.Protocol))
		//fmt.Println("rule.Port.ToUint16() => ", rule.Port.ToUint16())
		//fmt.Println("p.RemotePort => ", p.RemotePort)
		if (rule.Proto == packet.TypeName(p.Protocol) || rule.Proto == "any") && rule.Port.ToUint16() == p.RemotePort {
			if len(rule.Host) == 0 {
				return rule.Action
			}
			for _, host := range rule.Host {
				_, network, err := net.ParseCIDR(host)
				if err == nil {
					if network.Contains(p.RemoteIP.ToNetIP()) {
						return rule.Action
					}
				} else if host == p.RemoteIP.String() {
					return rule.Action
				}
			}
		}
	}
	// Default to deny if no matching rule is found
	return "deny"
}

func (ic *OutboundController) Close() error {
	ic.closed.Store(true)
	return ic.inside.Close()
}
