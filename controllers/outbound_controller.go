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
	"io"
	"net"
	"runtime"
)

var _ interfaces.OutboundController = &OutboundController{}

// OutboundController 出站控制器 必须实现 interfaces.OutboundController 接口
type OutboundController struct {
	outside     udp.Conn
	remotes     map[api.VpnIp]*host.HostInfo
	lighthouses []*host.HostInfo
	localVpnIP  api.VpnIp
	logger      *logrus.Logger
	cfg         *config.Config
}

func (oc *OutboundController) SendToRemote(out []byte, addr *udp.Addr) error {
	oc.logger.WithField("addr", addr).Info("出站流量 SendToRemote")
	return oc.outside.WriteTo(out, addr)
}

func (oc *OutboundController) Send(out []byte, addr string) error {
	ip, err := api.ParseVpnIp(addr)
	if err != nil {
		return err
	}
	conn, ok := oc.remotes[ip]
	if !ok {
		for _, lighthouse := range oc.lighthouses {
			if lighthouse != nil {
				oc.logger.WithField("目标地址", addr).
					WithField("灯塔地址", lighthouse.Remote).
					Info("出站流量转发到灯塔 OutboundController => Lighthouse")
				return oc.outside.WriteTo(out, lighthouse.Remote)
			}
		}

		return fmt.Errorf("host %s not found", addr)

	}
	oc.logger.WithField("目标地址", addr).
		WithField("目标远程地址", conn.Remote).
		Info("出站流量")
	return oc.outside.WriteTo(out, conn.Remote)
}

func (oc *OutboundController) Start(ctx context.Context) error {
	// 解析监听主机地址
	listenHost, err := resolveListenHost(oc.cfg.Listen.Host)
	if err != nil {
		return err
	}

	// 设置 UDP 服务器
	udpServer, err := udp.NewListener(oc.logger, listenHost.IP, oc.cfg.Listen.Port, oc.cfg.Listen.Routines > 1, oc.cfg.Listen.Batch)
	if err != nil {
		return err
	}
	udpServer.ReloadConfig(oc.cfg)
	oc.outside = udpServer

	// 如果端口是动态的，则获取端口
	if oc.cfg.Listen.Port == 0 {
		uPort, err := udpServer.LocalAddr()
		if err != nil {
			return err
		}
		oc.cfg.Listen.Port = int(uPort.Port)
	}

	// 配置静态主机映射
	oc.configureStaticHostMap()

	// 获取灯塔信息
	oc.lighthouses = oc.getLighthouses()

	addr, err := oc.outside.LocalAddr()
	if err != nil {
		return err
	}
	oc.logger.WithField("udpAddr", addr).Info("OutboundController is up")
	return nil
}

func resolveListenHost(rawListenHost string) (*net.IPAddr, error) {
	if rawListenHost == "[::]" {
		// Old guidance was to provide the literal `[::]` in `listen.host` but that won't resolve.
		return &net.IPAddr{IP: net.IPv6zero}, nil
	}
	return net.ResolveIPAddr("ip", rawListenHost)
}

func (oc *OutboundController) configureStaticHostMap() {
	for k, v := range oc.cfg.StaticHostMap {
		ip := net.ParseIP(k)
		if ip == nil {
			oc.logger.WithField("ip", k).Error("Invalid IP address")
			continue
		}
		udpAddr, err := net.ResolveUDPAddr("udp", v[0])
		if err != nil {
			oc.logger.WithError(err).WithField("ip", k).Error("Error resolving UDP address")
			continue
		}
		vpnIp := api.Ip2VpnIp(ip)
		oc.remotes[vpnIp] = &host.HostInfo{
			Remote: &udp.Addr{
				IP:   udpAddr.IP,
				Port: uint16(udpAddr.Port),
			},
			Remotes: host.RemoteList{},
			VpnIp:   vpnIp,
		}
	}
}

func (oc *OutboundController) getLighthouses() []*host.HostInfo {
	var lighthouses []*host.HostInfo
	for _, ip := range oc.cfg.Lighthouse.Hosts {
		vpnIp, err := api.ParseVpnIp(ip)
		if err != nil {
			oc.logger.WithError(err).WithField("lighthouse", ip).Error("解析VPN地址失败")
			continue
		}
		if host, ok := oc.remotes[vpnIp]; ok {
			lighthouses = append(lighthouses, host)
		} else {
			oc.logger.WithField("lighthouse", vpnIp).Error("灯塔未配置静态地址映射")
		}
	}
	return lighthouses
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

func (oc *OutboundController) handlePacket(addr *udp.Addr, p []byte, internalWriter io.Writer) {
	pk := &packet.Packet{}

	// 解析数据包
	if err := utils.ParsePacket(p, false, pk); err != nil {
		oc.logger.WithError(err).Error("解析数据包出错")
		return
	}

	oc.logger.WithField("远程地址", addr).
		WithField("源地址", pk.LocalIP).
		WithField("目标地址", pk.RemoteIP).
		WithField("原始数据", p).
		Info("入站流量")

	// 更新 remotes 映射表
	oc.updateRemotes(pk, addr)

	// 本地网卡访问本地地址
	if oc.localVpnIP.String() == pk.LocalIP.String() {
		oc.handleLocalVpnAddress(p, pk, internalWriter)
		return
	}

	// 远程访问本地地址，需要写入网卡且回应给远程
	if oc.localVpnIP.String() == pk.RemoteIP.String() {
		if _, err := internalWriter.Write(p); err != nil {
			oc.logger.WithError(err).Error("写入数据出错")
		}
		if err := oc.outside.WriteTo(p, addr); err != nil {
			oc.logger.WithError(err).WithField("addr", addr).Error("数据转发到远程")
		}
		return
	}

	// 处理目标地址是灯塔的情况
	oc.handleLighthouses(p, addr)
}

// 更新 remotes 映射表
func (oc *OutboundController) updateRemotes(pk *packet.Packet, addr *udp.Addr) {
	if _, ok := oc.remotes[pk.LocalIP]; !ok {
		oc.remotes[pk.LocalIP] = &host.HostInfo{
			Remote: addr,
			VpnIp:  pk.LocalIP,
		}
	}
}

// 处理目标地址是本地VPN地址的情况
func (oc *OutboundController) handleLocalVpnAddress(p []byte, pk *packet.Packet, internalWriter io.Writer) {
	// 本地VPN地址 => 写入到本地网卡
	fmt.Println("写入本地网卡 => ", p)
	replaceAddresses(p, pk.RemoteIP, pk.LocalIP)
	if _, err := internalWriter.Write(p); err != nil {
		oc.logger.WithError(err).Error("写入数据出错")
	}
}

// 处理目标地址是灯塔的情况
func (oc *OutboundController) handleLighthouses(p []byte, addr *udp.Addr) {
	for _, lighthouse := range oc.lighthouses {
		if lighthouse != nil {
			oc.logger.WithField("目标地址", addr).
				WithField("灯塔地址", lighthouse.Remote).
				Info("出站流量转发到灯塔")

			// 如果本地没有远程连接，将数据包转发到灯塔
			if err := oc.outside.WriteTo(p, lighthouse.Remote); err != nil {
				oc.logger.WithError(err).Error("数据转发到灯塔出错")
			}
		}
	}
}

// Listen 监听出站连接，并根据目标地址将数据包转发到相应的目标
func (oc *OutboundController) Listen(internalWriter io.Writer) {
	runtime.LockOSThread()
	oc.outside.ListenOut(func(addr *udp.Addr, out []byte, p []byte) {
		oc.handlePacket(addr, p, internalWriter)
	})
}

func (oc *OutboundController) Close() error {
	return oc.outside.Close()
}
