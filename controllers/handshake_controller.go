package controllers

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
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

	StartTime        time.Time            // 开始时间
	LastCompleteTime time.Time            // 最后一次握手完成时间
	Ready            bool                 // 是否就绪
	Counter          int                  // 尝试计数器
	LastRemotes      []net.Addr           // 上次发送握手消息的远程地址
	PacketStore      []*host.CachedPacket // 待发送的握手数据包
	HostInfo         *host.HostInfo       // 主机信息
}

func (h *HandshakeHostInfo) String() string {
	marshal, err := json.Marshal(h)
	if err != nil {
		return ""
	}
	return string(marshal)
}

var _ interfaces.HandshakeController = &HandshakeController{}

// HandshakeController 实现 HandshakeController 接口的握手控制器
type HandshakeController struct {
	sync.RWMutex
	handshakeHostsRwMutex sync.RWMutex
	localVIP              api.VpnIP
	handshakeHosts        map[api.VpnIP]*HandshakeHostInfo // 主机信息列表
	config                *config.HandshakeConfig          // 握手配置
	outboundTimer         *time.Timer                      // 发送握手消息的定时器
	outboundTrigger       chan HandshakeRequest            // 触发发送握手消息的通道
	logger                *logrus.Logger                   // 日志记录器
	messageMetrics        *pmetrics.MessageMetrics         // 消息统计
	ow                    interfaces.OutsideWriter
	// 外部连接
	mainHostMap     *host.HostMap // 主机地图
	lightHouses     map[api.VpnIP]*host.HostInfo
	lighthouse      interfaces.LighthouseController
	metricInitiated metrics.Counter // 握手初始化计数器
	metricTimedOut  metrics.Counter // 握手超时计数器
	localIndexID    uint32          // 本地节点标识
}

type HandshakeRequest struct {
	VIP    api.VpnIP
	Packet []byte
}

// NewHandshakeController 创建一个新的 HandshakeController 实例
func NewHandshakeController(logger *logrus.Logger, mainHostMap *host.HostMap, lightHouse *struct{}, ow interfaces.OutsideWriter, config config.HandshakeConfig, localVIP api.VpnIP, lightHouses map[api.VpnIP]*host.HostInfo) *HandshakeController {
	index, err := generateIndex()
	if err != nil {
		panic(err)
	}
	return &HandshakeController{
		localVIP:        localVIP,
		handshakeHosts:  make(map[api.VpnIP]*HandshakeHostInfo),
		config:          ApplyDefaultHandshakeConfig(&config),
		outboundTimer:   time.NewTimer(config.TryInterval),
		outboundTrigger: make(chan HandshakeRequest, config.TriggerBuffer),
		metricInitiated: metrics.GetOrRegisterCounter("handshake_manager.initiated", nil),
		metricTimedOut:  metrics.GetOrRegisterCounter("handshake_manager.timed_out", nil),
		logger:          logger,
		mainHostMap:     mainHostMap,
		lightHouses:     lightHouses,
		ow:              ow,
		localIndexID:    index,
	}
}

func (hc *HandshakeController) HandleRequest(rAddr *udp.Addr, pk *packet.Packet, h *header.Header, p []byte) {
	hc.logger.
		WithField("vpnIP", pk.RemoteIP).
		WithField("addr", rAddr).
		WithField("type", h.MessageType).
		WithField("subtype", h.MessageSubtype).
		Debug("Handle handshake requests")

	hc.mainHostMap.AddHost(pk.RemoteIP, rAddr)

	switch h.MessageSubtype {
	case header.HostHandshakeRequest:
		hc.handleHostHandshakeRequest(rAddr, pk.RemoteIP)
	case header.HostHandshakeReply:
		hc.handleHostHandshakeReply(rAddr, pk.RemoteIP)
	}
}

func (hc *HandshakeController) handleHostHandshakeRequest(addr *udp.Addr, vip api.VpnIP) {
	replyPacket, err := hc.buildHandshakeHostReplyPacket(vip)
	if err != nil {
		hc.logger.WithError(err).Error("Failed to build handshake host reply packet")
		return
	}

	hc.AddHandshakeHost(vip, addr, replyPacket)

	// 执行单次打洞的函数
	punch := func(vpnPeer *udp.Addr) {
		if vpnPeer == nil {
			return
		}
		go func() {
			// 可选：根据需要设置打洞操作的延迟
			time.Sleep(time.Second)

			// 发送打洞数据包
			if err := hc.ow.WriteToAddr(replyPacket, vpnPeer.NetAddr()); err != nil {
				hc.logger.WithError(err).Error("Failed to send punch packet")
			} else {
				hc.logger.WithFields(logrus.Fields{
					"vpnPeer": vpnPeer.String(),
					"vpnIP":   vip,
				}).Info("Sent punch packet")
			}
		}()
	}

	punch(addr)
}

func (hc *HandshakeController) handleHostHandshakeReply(addr *udp.Addr, vip api.VpnIP) {
	hc.UpdateHandshakeHost(vip, addr)
}

func (hc *HandshakeController) AddHandshakeHost(vip api.VpnIP, addr *udp.Addr, pk []byte) {
	hc.handshakeHostsRwMutex.Lock()
	defer hc.handshakeHostsRwMutex.Unlock()

	if _, exists := hc.handshakeHosts[vip]; !exists {
		hc.handshakeHosts[vip] = &HandshakeHostInfo{
			StartTime:   time.Now(),
			HostInfo:    &host.HostInfo{VpnIp: vip, Remote: addr},
			LastRemotes: []net.Addr{addr},
			packet:      pk,
		}
	}
}

func (hc *HandshakeController) UpdateHandshakeHost(vip api.VpnIP, addr *udp.Addr) {
	hc.handshakeHostsRwMutex.Lock()
	defer hc.handshakeHostsRwMutex.Unlock()

	if h, exists := hc.handshakeHosts[vip]; exists {
		h.Lock()
		defer h.Unlock()
		h.HostInfo.VpnIp = vip
		h.HostInfo.Remote = addr
		h.LastRemotes = append(h.LastRemotes, addr)
		h.LastCompleteTime = time.Now()
		h.Ready = true
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
		handshakeHostTicker := time.NewTicker(hc.config.SyncLighthouse)
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
		syncLighthouseTicker := time.NewTicker(hc.config.SyncLighthouse)
		defer syncLighthouseTicker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-syncLighthouseTicker.C:
				for k, v := range hc.mainHostMap.GetAllHostMap() {
					fmt.Printf("host: %s info%v\n", k, v)
				}
				hc.syncLighthouse(ctx)
			}
		}
	}()

	return nil
}

// handshakeAllHosts 对所有主机进行握手
func (hc *HandshakeController) handshakeAllHosts(ctx context.Context) {
	for vip, host := range hc.mainHostMap.GetAllHostMap() {
		if vip == hc.localVIP || hc.lightHouses[vip] != nil || hc.lighthouse.IsLighthouse() {
			continue
		}
		handshakePacket, err := hc.buildHandshakeHostRequestPacket(vip)
		if err != nil {
			hc.logger.WithError(err).Error("Failed to build handshake host reply packet")
			return
		}

		hc.logger.
			WithField("vpnIP", vip).
			WithField("addr", host.Remote).
			WithField("localIndex", hc.localIndexID).
			Debug("send host handshake packet")
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
		p, err := hc.buildLightHouseAndHostSyncPacket(lightHouse.VpnIp)
		if err != nil {
			hc.logger.WithError(err).Error("Failed to build handshake and host sync packet")
			continue
		}
		hc.logger.
			WithField("lightHouse", lightHouse.VpnIp).
			WithField("addr", lightHouse.Remote).
			WithField("localIndex", hc.localIndexID).
			Debug("Send Lighthouse sync handshake packet")
		if err := hc.Handshake(lightHouse.VpnIp, p); err != nil {
			hc.logger.Errorf("Error initiating handshake for %s: %v", lightHouse.VpnIp, err)
		}
		//hc.logger.
		//	WithField("lighthouse", lightHouse.VpnIP).
		//	Info("发送灯塔同步请求")
		//if err := hc.ow.WriteTo(p, lightHouse.Remote); err != nil {
		//	hc.logger.WithError(err).Error("Failed to send handshake packet to lighthouse")
		//}
	}
}

// Handshake 实现 HandshakeController 接口，启动针对指定 VPN IP 的握手过程
func (hc *HandshakeController) Handshake(vip api.VpnIP, packet []byte) error {
	hc.handshakeHostsRwMutex.Lock()
	defer hc.handshakeHostsRwMutex.Unlock()
	hh, ok := hc.handshakeHosts[vip]
	if !ok {
		// 创建新的握手主机信息
		hh = &HandshakeHostInfo{
			StartTime: time.Now(),
			packet:    packet,
			HostInfo: &host.HostInfo{
				VpnIp: vip,
			},
		}
		hc.handshakeHosts[vip] = hh
	} else {
		hh.Lock()
		defer hh.Unlock()

		hc.logger.
			WithField("vpnIP", vip).
			WithField("addr", hh.HostInfo.Remote).
			WithField("Ready", hh.Ready).
			WithField("LastCompleteTime", hh.LastCompleteTime).
			Debugf("Handshake for %s already complete, skipping", vip)

		if hh.Ready && time.Since(hh.LastCompleteTime) < hc.config.HandshakeHost {
			return nil
		}

		hh.packet = packet
		hh.StartTime = time.Now()
		hh.LastCompleteTime = time.Time{}
		hh.Ready = false
		hh.Counter = 0
		hh.LastRemotes = nil
		hh.PacketStore = nil
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
	hc.handshakeHostsRwMutex.Lock()
	handshakeHostInfo, exists := hc.handshakeHosts[hr.VIP]
	if !exists {
		hc.handshakeHostsRwMutex.Unlock()
		return
	}
	hc.handshakeHostsRwMutex.Unlock()

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

	// 转换为 net.Addr 类型的地址列表
	var netRemoteAddrList []net.Addr

	// 发送握手消息到远程地址列表中的每个地址
	for _, remoteAddr := range remoteAddrList {
		hc.logger.
			WithField("vpnIP", hr.VIP).
			WithField("addr", remoteAddr).
			WithField("localIndex", hc.localIndexID).
			Info("Send handshake packet")
		if err := hc.ow.WriteToAddr(hr.Packet, remoteAddr); err != nil {
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

func (hc *HandshakeController) buildHostHandshakePacket(vip api.VpnIP) ([]byte, error) {
	h, err2 := header.BuildHandshakeAndHostPunch(hc.localIndexID, 0)
	if err2 != nil {
		return nil, err2
	}

	p := (&packet.Packet{
		LocalIP:    hc.localVIP,
		RemoteIP:   vip,
		LocalPort:  0,
		RemotePort: 0,
		Protocol:   packet.ProtoUDP,
		Fragment:   false,
	}).Encode()

	var buf bytes.Buffer
	buf.Write(h)
	buf.Write(p)
	additionalData := make([]byte, 4)
	buf.Write(additionalData)
	return buf.Bytes(), nil
}

// handleOutboundTimerTick 处理传出握手消息的定时器触发
func (hc *HandshakeController) handleOutboundTimerTick() {
	hc.handshakeHostsRwMutex.Lock()
	defer hc.handshakeHostsRwMutex.Unlock()

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
func (hc *HandshakeController) deleteHandshakeInfo(vpnIP api.VpnIP) {
	hc.handshakeHostsRwMutex.Lock()
	defer hc.handshakeHostsRwMutex.Unlock()
	delete(hc.handshakeHosts, vpnIP)
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
	HandshakeHost:  30 * time.Second,
	SyncLighthouse: 60 * time.Second,
	TryInterval:    10 * time.Second, // 尝试间隔为10秒
	Retries:        3,                // 尝试次数为3次
	TriggerBuffer:  10,               // 触发缓冲为10
	UseRelays:      false,            // 不使用中继
}

// ApplyDefaultHandshakeConfig 将提供的 HandshakeConfig 按照默认配置进行填充，并返回填充后的结果
func ApplyDefaultHandshakeConfig(config *config.HandshakeConfig) *config.HandshakeConfig {
	defaultConfig := DefaultHandshakeConfig

	if config == nil {
		return &defaultConfig
	}

	if config.HandshakeHost == 0 {
		config.HandshakeHost = defaultConfig.HandshakeHost
	}

	if config.SyncLighthouse == 0 {
		config.SyncLighthouse = defaultConfig.SyncLighthouse
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

func (hc *HandshakeController) buildHandshakeHostRequestPacket(vip api.VpnIP) ([]byte, error) {
	return hc.buildHandshakePacket(vip, header.HostHandshakeRequest)
}

func (hc *HandshakeController) buildHandshakeHostReplyPacket(vip api.VpnIP) ([]byte, error) {
	return hc.buildHandshakePacket(vip, header.HostHandshakeReply)
}

func (hc *HandshakeController) buildLightHouseAndHostSyncPacket(vip api.VpnIP) ([]byte, error) {
	h, err := header.BuildLightHouse(hc.localIndexID, header.HostSync, 0)
	if err != nil {
		return nil, err
	}
	pk, err := packet.BuildIPv4Packet(hc.localVIP.ToIP(), vip.ToIP(), packet.ProtoUDP, false)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	buf.Write(h)
	buf.Write(pk)
	tmp := make([]byte, 4)
	buf.Write(tmp)
	return buf.Bytes(), nil
}

func (hc *HandshakeController) buildHandshakePacket(vip api.VpnIP, ms header.MessageSubType) ([]byte, error) {
	h, err := header.BuildHandshake(hc.localIndexID, ms, 0)
	if err != nil {
		return nil, err
	}
	pk, err := packet.BuildIPv4Packet(hc.localVIP.ToIP(), vip.ToIP(), packet.ProtoUDP, false)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	buf.Write(h)
	buf.Write(pk)
	tmp := make([]byte, 4)
	buf.Write(tmp)
	return buf.Bytes(), nil
}
