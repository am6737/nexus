package controllers

import (
	"context"
	"fmt"
	"github.com/am6737/nexus/api"
	"github.com/am6737/nexus/api/interfaces"
	"github.com/am6737/nexus/config"
	"github.com/am6737/nexus/host"
	"github.com/am6737/nexus/transport/packet"
	"github.com/am6737/nexus/transport/protocol/udp"
	"github.com/am6737/nexus/utils"
	"github.com/sirupsen/logrus"
	"net"
	"runtime"
)

var _ interfaces.OutboundController = &OutboundController{}

// OutboundController 出站控制器 必须实现 interfaces.OutboundController 接口
type OutboundController struct {
	outside    udp.Conn
	remotes    map[api.VpnIp]*host.HostInfo
	localVpnIP api.VpnIp
	logger     *logrus.Logger
	cfg        *config.Config
}

func (oc *OutboundController) Send(out []byte, addr string) error {
	ip, err := api.ParseVpnIp(addr)
	if err != nil {
		return err
	}
	conn, ok := oc.remotes[ip]
	if !ok {
		return fmt.Errorf("host %s not found", addr)
	}
	return oc.outside.WriteTo(out, conn.Remote)
}

func (oc *OutboundController) Start(ctx context.Context) error {
	var (
		err           error
		listenHost    *net.IPAddr
		rawListenHost = oc.cfg.Listen.Host
		port          = oc.cfg.Listen.Port
		routines      = 1
		batch         = oc.cfg.Listen.Batch
		conn          udp.Conn
	)

	if rawListenHost == "[::]" {
		// Old guidance was to provide the literal `[::]` in `listen.host` but that won't resolve.
		listenHost = &net.IPAddr{IP: net.IPv6zero}

	} else {
		listenHost, err = net.ResolveIPAddr("ip", rawListenHost)
		if err != nil {
			//return nil, util.ContextualizeIfNeeded("Failed to resolve listen.host", err)
			return err
		}
	}

	oc.logger.Infof("OutboundController listening %q %d", listenHost.IP, port)
	udpServer, err := udp.NewListener(oc.logger, listenHost.IP, port, routines > 1, batch)
	if err != nil {
		//return nil, util.NewContextualError("Failed to open udp listener", m{"queue": i}, err)
		panic(err)
	}
	udpServer.ReloadConfig(oc.cfg)
	conn = udpServer

	oc.outside = conn

	// If port is dynamic, discover it before the next pass through the for loop
	// This way all routines will use the same port correctly
	if port == 0 {
		uPort, err := udpServer.LocalAddr()
		if err != nil {
			//return nil, util.NewContextualError("Failed to get listening port", nil, err)
			panic(err)
		}
		port = int(uPort.Port)
	}

	for k, v := range oc.cfg.StaticHostMap {
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
		oc.remotes[vip] = &host.HostInfo{
			Remote: &udp.Addr{
				IP:   udpAddr.IP,
				Port: uint16(udpAddr.Port),
			},
			Remotes: host.RemoteList{},
			VpnIp:   vip,
		}
	}

	addr, err := oc.outside.LocalAddr()
	if err != nil {
		oc.logger.WithError(err).Error("Failed to get udp listen address")
	}
	oc.logger.WithField("udpAddr", addr).Info("OutboundController is up")
	return nil
}

func replaceAddresses(out []byte, localIP api.VpnIp, remoteIP api.VpnIp) {
	copy(out[12:16], parseIP(localIP.String()))  // 将本地IP地址替换到目标IP地址的位置
	copy(out[16:20], parseIP(remoteIP.String())) // 将目标IP地址替换到源IP地址的位置
}

func parseIP(ipString string) []byte {
	// 解析 IPv4 地址字符串为 net.IP 类型
	ip := net.ParseIP(ipString)
	if ip == nil {
		fmt.Println("Invalid IP address:", ipString)
		return nil
	}
	// 将 net.IP 类型转换为 []byte 切片
	ipBytes := ip.To4()
	if ipBytes == nil {
		fmt.Println("Invalid IPv4 address:", ipString)
		return nil
	}
	return ipBytes
}

// Listen 监听出站连接，并根据目标地址将数据包转发到相应的目标
func (oc *OutboundController) Listen(internalWriter func(p []byte) (n int, err error)) {
	runtime.LockOSThread()
	oc.outside.ListenOut(func(addr *udp.Addr, out []byte, p []byte) {
		oc.logger.WithField("udpAddr", addr).Info("OutboundController Listen")

		pk := &packet.Packet{}

		// 解析数据包
		if err := utils.ParsePacket(p, false, pk); err != nil {
			oc.logger.WithError(err).Error("解析数据包出错")
			return
		}

		// 如果目标地址是本地VPN地址，将数据写入到本地的tun中
		if oc.localVpnIP.String() == pk.RemoteIP.String() {
			replaceAddresses(p, pk.RemoteIP, oc.localVpnIP)
			if _, err := internalWriter(p); err != nil {
				oc.logger.WithError(err).Error("写入数据出错")
			}
			return
		}

		// 获取目标地址对应的远程连接
		remoteConn, ok := oc.remotes[pk.RemoteIP]
		if !ok || remoteConn == nil {
			oc.logger.Warnf("未找到远程连接或连接为空: %s", pk.RemoteIP)
			return
		}

		// 将数据写入远程的连接中
		if err := oc.outside.WriteTo(p, remoteConn.Remote); err != nil {
			oc.logger.WithError(err).Error("写入数据到远程连接出错")
			return
		}
	})
}

func (oc *OutboundController) Close() error {
	return oc.outside.Close()
}
