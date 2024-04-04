package controllers

import (
	"context"
	"fmt"
	"github.com/am6737/nexus/api"
	"github.com/am6737/nexus/api/interfaces"
	"github.com/am6737/nexus/host"
	"github.com/am6737/nexus/transport/packet"
	"golang.org/x/net/ipv4"
	//pkudp "github.com/am6737/nexus/transport/packet/udp"
	"github.com/am6737/nexus/transport/protocol/udp"
	"github.com/am6737/nexus/transport/protocol/udp/header"
	"github.com/sirupsen/logrus"
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

	outside udp.Conn

	localVpnIP api.VpnIp

	sendFunc func(out []byte, addr *udp.Addr) error

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

	go func() {
		// 启动定时器，每秒进行一次握手
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
			case <-ticker.C:
				hc.startHandshakeWork()
				//for host, _ := range hc.hosts {
				//	hc.trigger <- host
				//}
			}
		}
	}()
	return nil
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
	//netAddr := &net.UDPAddr{
	//	IP:   addr.IP,
	//	Port: int(addr.Port),
	//}
	//conn, err := net.DialUDP("udp", nil, netAddr)
	//if err != nil {
	//	hc.logger.WithError(err).WithField("addr", addr).Error("failed to dial lighthouse")
	//	return
	//}
	//defer conn.Close()

	// 构建握手数据包
	hh, err := header.BuildHandshakePacket(0, 1)
	if err != nil {
		hc.logger.WithError(err).WithField("addr", addr).Error("failed to build handshake packet")
		return
	}

	h := ipv4.Header{
		Version:  1,
		Len:      20,
		Src:      hc.localVpnIP.ToIP(),
		Dst:      addr.IP,
		Protocol: packet.ProtoUDP,
		Options:  []byte{0, 1, 0, 2},
	}
	b, _ := h.Marshal()
	b = append(b, hh...)
	//todo
	//封装数据包
	//data, err := pkudp.Packet{}.Serialize()
	//if err != nil {
	//	hc.logger.WithError(err).WithField("addr", addr).Error("failed to serialize packet")
	//	return
	//}

	out := make([]byte, hc.mtu)
	// 将握手数据包写入输出缓冲区
	copy(out, b)

	// 将数据包写入到连接中
	err = hc.sendFunc(out, &addr)
	if err != nil {
		hc.logger.WithError(err).WithField("addr", addr).Error("failed to write handshake packet")
		return
	}

	hc.logger.WithField("addr", addr).WithField("packet header", hh).Info("handshake lighthouse")
}

// Handshake 执行给定 vpnIp 的握手
func (hc *HandshakeController) Handshake(vpnIp api.VpnIp) error {
	return nil
}

func (hc *HandshakeController) startLighthouseHandshake() {

	// 启动定时器，每秒进行一次握手
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			for _, lighthouse := range hc.lighthouses {
				fmt.Println("lighthouse.Remote.IP => ", lighthouse.Remote.IP)
				fmt.Println("lighthouse.Remote.IP => ", lighthouse.Remote.Port)
				hc.handshakeQueue <- udp.Addr{
					IP:   lighthouse.Remote.IP,
					Port: lighthouse.Remote.Port,
				}
			}
		}

		//for _, lighthouse := range hc.lighthouses {
		//fmt.Println("lighthouse.Remote.IP => ", lighthouse.Remote.IP)
		//fmt.Println("lighthouse.Remote.IP => ", lighthouse.Remote.Port)
		//hc.handshakeQueue <- udp.Addr{
		//	IP:   lighthouse.Remote.IP,
		//	Port: lighthouse.Remote.Port,
		//}
		//conn, err := net.DialUDP("udp", nil, &net.UDPAddr{
		//	IP:   lighthouse.Remote.IP,
		//	Port: int(lighthouse.Remote.Port),
		//})
		//fmt.Println("3333")
		//
		//if err != nil {
		//	hc.logger.WithError(err).WithField("lighthouse addr", lighthouse.Remote.String()).Error("failed to dial lighthouse")
		//	continue
		//}
		//defer conn.Close()
		//
		//fmt.Println("111")
		//
		//hc.hosts[vpnIp] = &host.HostInfo{
		//	Remote: lighthouse.Remote,
		//	VpnIp:  vpnIp,
		//}
		//fmt.Println("2222")
		//
		//hc.logger.WithField("conn", conn.RemoteAddr()).Info("handshake lighthouse")
	}
}
