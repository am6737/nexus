package controllers

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"github.com/am6737/nexus/api"
	"github.com/am6737/nexus/api/interfaces"
	"github.com/am6737/nexus/config"
	"github.com/am6737/nexus/host"
	pmetrics "github.com/am6737/nexus/metrics"
	"github.com/am6737/nexus/transport/packet"
	"github.com/am6737/nexus/transport/protocol/udp"
	"github.com/am6737/nexus/transport/protocol/udp/header"
	"github.com/rcrowley/go-metrics"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// HandshakeHostInfo 握手主机信息
type HandshakeHostInfo struct {
	sync.Mutex

	packet []byte

	StartTime   time.Time            // 开始时间
	Ready       bool                 // 是否就绪
	Counter     int                  // 尝试计数器
	LastRemotes []net.Addr           // 上次发送握手消息的远程地址
	PacketStore []*host.CachedPacket // 待发送的握手数据包
	HostInfo    *host.HostInfo       // 主机信息
}

var _ interfaces.HandshakeController = &HandshakeController{}

// HandshakeController 实现 HandshakeController 接口的握手控制器
type HandshakeController struct {
	sync.RWMutex
	localVIP        api.VpnIp
	handshakeHosts  map[api.VpnIp]*HandshakeHostInfo // 主机信息列表
	config          *config.HandshakeConfig          // 握手配置
	outboundTimer   *time.Timer                      // 发送握手消息的定时器
	outboundTrigger chan HandshakeRequest            // 触发发送握手消息的通道
	logger          *logrus.Logger                   // 日志记录器
	messageMetrics  *pmetrics.MessageMetrics         // 消息统计
	outside         udp.Conn                         // 外部连接
	mainHostMap     *host.HostMap                    // 主机地图
	lightHouses     map[api.VpnIp]*host.HostInfo
	metricInitiated metrics.Counter // 握手初始化计数器
	metricTimedOut  metrics.Counter // 握手超时计数器
	localIndexID    uint32          // 本地节点标识
}

type HandshakeRequest struct {
	VIP    api.VpnIp
	Packet []byte
}

// NewHandshakeController 创建一个新的 HandshakeController 实例
func NewHandshakeController(logger *logrus.Logger, mainHostMap *host.HostMap, lightHouse *struct{}, outside udp.Conn, config config.HandshakeConfig, localVIP api.VpnIp, lightHouses map[api.VpnIp]*host.HostInfo) *HandshakeController {
	index, err := generateIndex()
	if err != nil {
		panic(err)
	}
	return &HandshakeController{
		localVIP:        localVIP,
		handshakeHosts:  make(map[api.VpnIp]*HandshakeHostInfo),
		config:          ApplyDefaultHandshakeConfig(&config),
		outboundTimer:   time.NewTimer(config.TryInterval),
		outboundTrigger: make(chan HandshakeRequest, config.TriggerBuffer),
		metricInitiated: metrics.GetOrRegisterCounter("handshake_manager.initiated", nil),
		metricTimedOut:  metrics.GetOrRegisterCounter("handshake_manager.timed_out", nil),
		logger:          logger,
		mainHostMap:     mainHostMap,
		lightHouses:     lightHouses,
		outside:         outside,
		localIndexID:    index,
	}
}

// Start 启动 HandshakeController，监听发送握手消息的触发通道和定时器
func (hc *HandshakeController) Start(ctx context.Context) error {
	hc.logger.Info("Starting handshake controller")

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case hr := <-hc.outboundTrigger:
				hc.handleOutbound(hr, true)
			case <-hc.outboundTimer.C:
				//hc.handleOutboundTimerTick()
			}
		}
	}()

	hc.handshakeAllHosts(ctx)
	hc.syncLighthouse(ctx)

	go func() {
		handshakeHostTicker := time.NewTicker(10 * time.Second)
		defer handshakeHostTicker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-handshakeHostTicker.C:
				hc.handshakeAllHosts(ctx)
			}
		}
	}()

	go func() {
		syncLighthouseTicker := time.NewTicker(30 * time.Second)
		defer syncLighthouseTicker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-syncLighthouseTicker.C:
				hc.syncLighthouse(ctx)
			}
		}
	}()

	return nil
}

// handshakeAllHosts 对所有主机进行握手
func (hc *HandshakeController) handshakeAllHosts(ctx context.Context) {
	fmt.Println("hc.mainHostMap.GetAllHostMap() => ", hc.mainHostMap.GetAllHostMap())
	for vip, host := range hc.mainHostMap.GetAllHostMap() {
		handshakePacket, err := hc.buildHostHandshakePacket(vip)
		if err != nil {
			return
		}
		hc.logger.
			WithField("vpnIP", vip).
			WithField("addr", host.Remote).
			WithField("localIndex", hc.localIndexID).
			Info("send host handshake packet")
		if err := hc.Handshake(vip, handshakePacket); err != nil {
			hc.logger.Errorf("Error initiating handshake for %s: %v", vip, err)
		}
	}
}

func (hc *HandshakeController) syncLighthouse(ctx context.Context) {
	for _, lightHouse := range hc.lightHouses {
		if lightHouse.VpnIp == hc.localVIP {
			hc.logger.Warn("Lighthouse is localhost")
			continue
		}
		p, err := hc.buildHandshakeAndHostSyncPacket(lightHouse.VpnIp)
		if err != nil {
			hc.logger.WithError(err).Error("Failed to build handshake and host sync packet")
			continue
		}
		hc.logger.
			WithField("lightHouse", lightHouse.VpnIp).
			WithField("addr", lightHouse.Remote).
			WithField("localIndex", hc.localIndexID).
			Info("send lightHouse sync handshake packet")
		if err := hc.Handshake(lightHouse.VpnIp, p); err != nil {
			hc.logger.Errorf("Error initiating handshake for %s: %v", lightHouse.VpnIp, err)
		}
		//hc.logger.
		//	WithField("lighthouse", lightHouse.VpnIp).
		//	Info("发送灯塔同步请求")
		//if err := hc.outside.WriteTo(p, lightHouse.Remote); err != nil {
		//	hc.logger.WithError(err).Error("Failed to send handshake packet to lighthouse")
		//}
	}
}

func (hc *HandshakeController) buildHandshakeAndHostSyncPacket(vip api.VpnIp) ([]byte, error) {
	handshakePacket, err := generateHandshakeAndHostSyncPacket(hc.localIndexID)
	if err != nil {
		return nil, err
	}

	pv4Packet, err := packet.BuildIPv4Packet(hc.localVIP.ToIP(), vip.ToIP(), packet.ProtoUDP, false)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	buf.Write(handshakePacket)
	buf.Write(pv4Packet)
	additionalData := make([]byte, 4)
	buf.Write(additionalData)
	return buf.Bytes(), nil
}

// Handshake 实现 HandshakeController 接口，启动针对指定 VPN IP 的握手过程
func (hc *HandshakeController) Handshake(vip api.VpnIp, packet []byte) error {
	hc.Lock()
	defer hc.Unlock()

	// 检查是否已经存在相同 VPN IP 的握手信息
	//h, exists := hc.handshakeHosts[vip]
	//if exists {
	//	h.packet = packet
	//	return nil
	//}

	//创建新的握手主机信息
	hc.handshakeHosts[vip] = &HandshakeHostInfo{
		packet:    packet,
		StartTime: time.Now(),
		HostInfo: &host.HostInfo{
			Remote:        nil,
			Remotes:       host.RemoteList{},
			RemoteIndexId: 0,
			LocalIndexId:  0,
			VpnIp:         vip,
		},
	}

	// 触发发送握手消息
	select {
	case hc.outboundTrigger <- HandshakeRequest{
		VIP:    vip,
		Packet: packet,
	}:
	default:
	}

	return nil
}

// handleOutbound 处理传出的握手消息
func (hc *HandshakeController) handleOutbound(hr HandshakeRequest, lighthouseTriggered bool) {
	// 获取握手主机信息
	handshakeHostInfo, exists := hc.handshakeHosts[hr.VIP]
	if !exists {
		return
	}
	handshakeHostInfo.Lock()
	defer handshakeHostInfo.Unlock()

	// 如果已经超过重试次数，则终止握手过程
	if handshakeHostInfo.Counter >= hc.config.Retries {
		//fmt.Println("握手超时次数 => ", handshakeHostInfo.Counter)
		//hc.metricTimedOut.Inc(1)
		//hc.deleteHandshakeInfo(hr.VIP)
		//return
	}

	// 获取远程地址列表
	remoteAddrList := hc.mainHostMap.GetRemoteAddrList(hr.VIP)

	//fmt.Println("remoteAddrList => ", remoteAddrList)

	// 转换为 net.Addr 类型的地址列表
	var netRemoteAddrList []net.Addr

	// 发送握手消息到远程地址列表中的每个地址
	for _, remoteAddr := range remoteAddrList {
		//fmt.Println("handshakePacket => ", hr.Packet)
		if err := hc.outside.WriteTo(hr.Packet, remoteAddr); err != nil {
			hc.logger.Errorf("failed to send handshake packet to %s: %v", remoteAddr, err)
			continue
		}
		netRemoteAddrList = append(netRemoteAddrList,
			&net.UDPAddr{
				IP:   remoteAddr.IP,
				Port: int(remoteAddr.Port),
			})
	}

	// 更新握手主机信息
	handshakeHostInfo.Counter++
	handshakeHostInfo.LastRemotes = netRemoteAddrList
}

func (hc *HandshakeController) buildHostHandshakePacket(vip api.VpnIp) ([]byte, error) {
	// 生成握手消息
	handshakePacket, err := generateHandshakePacket(hc.localIndexID)
	if err != nil {
		hc.logger.Errorf("failed to generate handshake packet: %v", err)
		return nil, err
	}

	pv4Packet, err := packet.BuildIPv4Packet(hc.localVIP.ToIP(), vip.ToIP(), packet.ProtoUDP, false)
	if err != nil {
		hc.logger.Errorf("failed to build IPv4 packet: %v", err)
		return nil, err
	}

	var buf bytes.Buffer
	buf.Write(handshakePacket)
	buf.Write(pv4Packet)
	additionalData := make([]byte, 4)
	buf.Write(additionalData)
	return buf.Bytes(), nil
}

// handleOutboundTimerTick 处理传出握手消息的定时器触发
func (hc *HandshakeController) handleOutboundTimerTick() {
	hc.Lock()
	defer hc.Unlock()

	for vpnIP, host := range hc.handshakeHosts {
		select {
		case hc.outboundTrigger <- HandshakeRequest{
			VIP:    vpnIP,
			Packet: host.packet,
		}:
		default:
		}
	}
	hc.outboundTimer.Reset(hc.config.TryInterval)
}

// deleteHandshakeInfo 删除指定 VPN IP 的握手信息
func (hc *HandshakeController) deleteHandshakeInfo(vpnIP api.VpnIp) {
	delete(hc.handshakeHosts, vpnIP)
}

// generateHandshakePacket 生成握手消息
func generateHandshakePacket(localIndexID uint32) ([]byte, error) {
	return header.BuildHandshakePacket(localIndexID, 0, 0)
}

// generateHandshakeAndHostSyncPacket 生成握手和同步节点消息
func generateHandshakeAndHostSyncPacket(localIndexID uint32) ([]byte, error) {
	return header.BuildHandshakePacket(localIndexID, header.HostSync, 0)
}

// generateIndex 生成一个唯一的本地索引 ID
func generateIndex() (uint32, error) {
	b := make([]byte, 4)

	// Let zero mean we don't know the ID, so don't generate zero
	var index uint32
	for index == 0 {
		_, err := rand.Read(b)
		if err != nil {
			return 0, err
		}

		index = binary.BigEndian.Uint32(b)
	}
	return index, nil
}

// hsTimeout 计算握手超时时间
func hsTimeout(tries int, interval time.Duration) time.Duration {
	return time.Duration(tries / 2 * ((2 * int(interval)) + (tries-1)*int(interval)))
}

// DefaultHandshakeConfig 是默认的 HandshakeConfig 配置
var DefaultHandshakeConfig = config.HandshakeConfig{
	TryInterval:   10 * time.Second, // 尝试间隔为10秒
	Retries:       3,                // 尝试次数为3次
	TriggerBuffer: 10,               // 触发缓冲为10
	UseRelays:     false,            // 不使用中继
}

// ApplyDefaultHandshakeConfig 将提供的 HandshakeConfig 按照默认配置进行填充，并返回填充后的结果
func ApplyDefaultHandshakeConfig(config *config.HandshakeConfig) *config.HandshakeConfig {
	defaultConfig := DefaultHandshakeConfig

	if config == nil {
		return &defaultConfig
	}

	// 检查 TryInterval 是否为零值或者为默认值，如果是，则使用默认值
	if config.TryInterval == 0 {
		config.TryInterval = defaultConfig.TryInterval
	}

	// 检查 Retries 是否为零值或者为默认值，如果是，则使用默认值
	if config.Retries == 0 {
		config.Retries = defaultConfig.Retries
	}

	// 检查 TriggerBuffer 是否为零值或者为默认值，如果是，则使用默认值
	if config.TriggerBuffer == 0 {
		config.TriggerBuffer = defaultConfig.TriggerBuffer
	}

	// 检查 UseRelays 是否为默认值，如果是，则使用默认值
	if !config.UseRelays {
		config.UseRelays = defaultConfig.UseRelays
	}

	return config
}
