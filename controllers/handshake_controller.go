package controllers

import (
	"context"
	"github.com/am6737/nexus/api"
	"github.com/am6737/nexus/api/interfaces"
	"github.com/am6737/nexus/host"
	"github.com/am6737/nexus/transport/protocol/udp"
	"github.com/am6737/nexus/transport/protocol/udp/header"
	"github.com/sirupsen/logrus"
	"net"
	"time"
)

var _ interfaces.HandshakeController = &HandshakeController{}

// HandshakeController 握手控制器 必须实现 interfaces.HandshakeController 接口
type HandshakeController struct {
	// trigger 用于触发给定 vpnIp 的出站握手
	trigger chan api.VpnIp
	// lighthouses 存储灯塔的地址
	lighthouses map[api.VpnIp]*host.HostInfo

	hosts map[api.VpnIp]*host.HostInfo

	// handshakeQueue 用于存储需要进行握手的地址
	handshakeQueue chan udp.Addr

	mtu int

	logger *logrus.Logger
}

// NewHandshakeController 创建一个新的 HandshakeController 实例
func NewHandshakeController(logger *logrus.Logger) *HandshakeController {
	return &HandshakeController{
		//trigger:        trigger,
		logger:         logger,
		hosts:          make(map[api.VpnIp]*host.HostInfo),
		handshakeQueue: make(chan udp.Addr),
	}
}

func (hc *HandshakeController) Start(ctx context.Context) error {
	//go hc.startHandshakeWork()
	go hc.startLighthouseHandshake()

	// 启动定时器，每秒进行一次握手
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			//for host, _ := range hc.hosts {
			//	hc.trigger <- host
			//}
		}
	}
}

// startHandshakeWork 处理给定地址的握手
func (hc *HandshakeController) startHandshakeWork() {
	for {
		select {
		case addr := <-hc.handshakeQueue:
			hc.performHandshake(addr)
		}
	}
}

func (hc *HandshakeController) performHandshake(addr udp.Addr) {
	netAddr := &net.UDPAddr{
		IP:   addr.IP,
		Port: int(addr.Port),
	}
	conn, err := net.DialUDP("udp", nil, netAddr)
	if err != nil {
		hc.logger.WithError(err).WithField("addr", addr).Error("failed to dial lighthouse")
		return
	}
	defer conn.Close()

	// 构建握手数据包
	hh, err := header.BuildHandshakePacket(0, 1)
	if err != nil {
		hc.logger.WithError(err).WithField("addr", addr).Error("failed to build handshake packet")
		return
	}

	out := make([]byte, hc.mtu)
	// 将握手数据包写入输出缓冲区
	copy(out, hh)

	// 将数据包写入到连接中
	_, err = conn.WriteTo(out, netAddr)
	if err != nil {
		hc.logger.WithError(err).WithField("addr", addr).Error("failed to write handshake packet")
		return
	}

	hc.logger.WithField("conn", conn.RemoteAddr()).WithField("packet", out).Info("handshake lighthouse")
}

// Handshake 执行给定 vpnIp 的握手
func (hc *HandshakeController) Handshake(vpnIp api.VpnIp) error {
	return nil
}

func (hc *HandshakeController) startLighthouseHandshake() {
	// 对灯塔进行握手
	for vpnIp, lighthouse := range hc.lighthouses {
		conn, err := net.DialUDP("udp", nil, &net.UDPAddr{
			IP:   lighthouse.Remote.IP,
			Port: int(lighthouse.Remote.Port),
		})
		if err != nil {
			hc.logger.WithError(err).WithField("lighthouse addr", lighthouse.Remote.String()).Error("failed to dial lighthouse")
			return
		}
		defer conn.Close()

		hc.hosts[vpnIp] = &host.HostInfo{
			Remote: lighthouse.Remote,
			VpnIp:  vpnIp,
		}

		hc.logger.WithField("conn", conn.RemoteAddr()).Info("handshake lighthouse")
	}
}
