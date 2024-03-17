package controllers

import (
	"context"
	"errors"
	"fmt"
	"github.com/am6737/nexus/api"
	"github.com/am6737/nexus/api/interfaces"
	"github.com/am6737/nexus/config"
	"github.com/am6737/nexus/host"
	"github.com/am6737/nexus/ifce"
	"github.com/am6737/nexus/transport/packet"
	"github.com/am6737/nexus/transport/protocol/udp"
	"github.com/am6737/nexus/tun"
	"github.com/am6737/nexus/utils"
	"github.com/sirupsen/logrus"
	"io"
	"net"
	"os"
	"runtime"
	"sync/atomic"
)

var _ interfaces.InboundController = &InboundController{}

// InboundController 入站控制器 必须实现 interfaces.InboundController 接口
type InboundController struct {
	mtu        int
	closed     atomic.Bool
	remotes    map[api.VpnIp]*host.HostInfo
	localVpnIP api.VpnIp
	outside    udp.Conn
	inside     tun.Device
	logger     *logrus.Logger
	cfg        *config.Config
}

func (ic *InboundController) Start(ctx context.Context) error {
	for k, v := range ic.cfg.StaticHostMap {
		ip := net.ParseIP(k)
		if ip == nil {
			fmt.Println("Invalid IP address")
			continue
		}
		udpAddr, err := net.ResolveUDPAddr("udp", v[0])
		if err != nil {
			fmt.Println("Error resolving UDP address:", err)
			continue
		}
		vip := api.Ip2VpnIp(ip)
		ic.remotes[vip] = &host.HostInfo{
			Remote: &udp.Addr{
				IP:   udpAddr.IP,
				Port: uint16(udpAddr.Port),
			},
			Remotes: host.RemoteList{},
			VpnIp:   vip,
		}
	}

	if err := ic.inside.Up(); err != nil {
		if err := ic.inside.Close(); err != nil {
			ic.logger.WithError(err).Error("Failed to up tun device")
		}
		ic.logger.Fatal(err)
	}
	return nil
}

func (ic *InboundController) Send(p []byte) (n int, err error) {
	return ic.inside.Write(p)
}

func (ic *InboundController) Listen(outbound func(out []byte, addr string) error) {
	runtime.LockOSThread()
	p := &packet.Packet{}
	packet := make([]byte, ic.mtu)
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
		ic.consumeInsidePacket(packet[:n], p, ic.inside, outbound)
	}
}

func (ic *InboundController) consumeInsidePacket(data []byte, packet *packet.Packet, internalWriter io.Writer, outbound func(out []byte, addr string) error) {
	if err := utils.ParsePacket(data, false, packet); err != nil {
		ic.logger.WithField("packet", packet).Debugf("Error while validating outbound packet: %s", err)
		return
	}

	ic.logger.WithField("packet", packet).WithField("data", data).Info("Received outbound packet")

	if packet.RemoteIP == ic.localVpnIP {
		// Immediately forward packets from self to self.
		// This should only happen on Darwin-based and FreeBSD hosts, which
		// routes packets from the Nebula IP to the Nebula IP through the Nebula
		// TUN device.
		if ifce.ImmediatelyForwardToSelf {
			if _, err := internalWriter.Write(data); err != nil {
				ic.logger.WithError(err).Error("Failed to forward to tun")
			}
		}
		// Otherwise, drop. On linux, we should never see these packets - Linux
		// routes packets from the nebula IP to the nebula IP through the loopback device.
		return
	}

	fmt.Println("outbound out => ", data)

	host, ok := ic.remotes[packet.RemoteIP]
	if !ok {
		ic.logger.WithField("remoteIp", packet.RemoteIP).Warn("Host not found")
		return
	}
	if host.VpnIp != packet.RemoteIP {
		ic.logger.WithField("remoteIp", packet.RemoteIP).Warn("Host not found")
		return
	}

	ic.logger.WithField("remoteIp", host.Remote.IP).
		WithField("remotePort", host.Remote.Port).
		WithField("data", data).
		Info("consume packet forward to udp")

	if err := ic.outside.WriteTo(data, host.Remote); err != nil {
		ic.logger.WithError(err).Error("Failed to forward to udp")
	}

	//if err := outbound(data, packet.RemoteIP.String()); err != nil {
	//	ic.logger.WithError(err).Error("Error while forwarding outbound packet")
	//	return
	//}
}

func (ic *InboundController) Close() error {
	return ic.inside.Close()
}
