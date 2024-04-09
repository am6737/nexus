package controllers

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"github.com/am6737/nexus/api"
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

	StartTime   time.Time            // 开始时间
	Ready       bool                 // 是否就绪
	Counter     int                  // 尝试计数器
	LastRemotes []net.Addr           // 上次发送握手消息的远程地址
	PacketStore []*host.CachedPacket // 待发送的握手数据包
	HostInfo    *host.HostInfo       // 主机信息
}

// HandshakeController 实现 HandshakeController 接口的握手控制器
type HandshakeController struct {
	sync.RWMutex

	localVIP api.VpnIp

	hosts           map[api.VpnIp]*HandshakeHostInfo // 主机信息列表
	config          *config.HandshakeConfig          // 握手配置
	outboundTimer   *time.Timer                      // 发送握手消息的定时器
	outboundTrigger chan api.VpnIp                   // 触发发送握手消息的通道
	logger          *logrus.Logger                   // 日志记录器
	messageMetrics  *pmetrics.MessageMetrics         // 消息统计
	outside         udp.Conn                         // 外部连接
	mainHostMap     *host.HostMap                    // 主机地图
	//lightHouse      *LightHouse                      // 光明之屋
	//f               *Interface                       // 接口
	metricInitiated metrics.Counter // 握手初始化计数器
	metricTimedOut  metrics.Counter // 握手超时计数器

	localIndexID uint32
}

// NewHandshakeController 创建一个新的 HandshakeController 实例
func NewHandshakeController(logger *logrus.Logger, mainHostMap *host.HostMap, lightHouse *struct{}, outside udp.Conn, config config.HandshakeConfig, localVIP api.VpnIp) *HandshakeController {
	index, err := generateIndex()
	if err != nil {
		panic(err)
	}
	return &HandshakeController{
		localVIP:        localVIP,
		hosts:           make(map[api.VpnIp]*HandshakeHostInfo),
		config:          ApplyDefaultHandshakeConfig(&config),
		outboundTimer:   time.NewTimer(config.TryInterval),
		outboundTrigger: make(chan api.VpnIp, config.TriggerBuffer),
		logger:          logger,
		mainHostMap:     mainHostMap,
		//lightHouse:      lightHouse,
		outside: outside,
		//messageMetrics:  config.MessageMetrics,
		localIndexID: index,
	}
}

// Start 启动 HandshakeController，监听发送握手消息的触发通道和定时器
func (hc *HandshakeController) Start(ctx context.Context) error {
	hc.logger.Info("Starting handshake controller")
	go hc.handshakeAllHosts(ctx)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case vpnIP := <-hc.outboundTrigger:
				hc.handleOutbound(vpnIP, true)
			case <-hc.outboundTimer.C:
				hc.handleOutboundTimerTick()
			}
		}
	}()
	return nil
}

// handshakeAllHosts 对所有主机进行握手
func (hc *HandshakeController) handshakeAllHosts(ctx context.Context) {
	// 定期对所有主机进行握手
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				//hc.RLock()
				for vip := range hc.mainHostMap.Hosts {
					if err := hc.Handshake(vip); err != nil {
						hc.logger.Errorf("Error initiating handshake for %s: %v", vip, err)
					}
				}
				//hc.RUnlock()
			}
		}
	}()
}

// Handshake 实现 HandshakeController 接口，启动针对指定 VPN IP 的握手过程
func (hc *HandshakeController) Handshake(vip api.VpnIp) error {
	hc.Lock()
	defer hc.Unlock()

	// 检查是否已经存在相同 VPN IP 的握手信息
	//if _, exists := hc.hosts[vip]; exists {
	//	return errors.New("handshake already initiated for this VPN IP")
	//}

	// 创建新的握手主机信息
	hostInfo := &host.HostInfo{
		Remote:        nil,
		Remotes:       host.RemoteList{},
		RemoteIndexId: 0,
		LocalIndexId:  0,
		VpnIp:         vip,
	}
	handshakeHostInfo := &HandshakeHostInfo{
		StartTime: time.Now(),
		HostInfo:  hostInfo,
	}

	// 将新的握手主机信息添加到列表中
	hc.hosts[vip] = handshakeHostInfo

	// 触发发送握手消息
	select {
	case hc.outboundTrigger <- vip:
	default:
	}

	return nil
}

// handleOutbound 处理传出的握手消息
func (hc *HandshakeController) handleOutbound(vpnIP api.VpnIp, lighthouseTriggered bool) {
	// 获取握手主机信息
	handshakeHostInfo, exists := hc.hosts[vpnIP]
	if !exists {
		return
	}
	handshakeHostInfo.Lock()
	defer handshakeHostInfo.Unlock()

	// 如果已经超过重试次数，则终止握手过程
	if handshakeHostInfo.Counter >= hc.config.Retries {
		hc.metricTimedOut.Inc(1)
		hc.deleteHandshakeInfo(vpnIP)
		return
	}

	// 生成握手消息
	handshakePacket, err := generateHandshakePacket(hc.localIndexID)
	if err != nil {
		hc.logger.Errorf("failed to generate handshake packet: %v", err)
		return
	}

	pv4Packet, err := packet.BuildIPv4Packet(hc.localVIP.ToIP(), vpnIP.ToIP(), packet.ProtoUDP, false)
	if err != nil {
		hc.logger.Errorf("failed to build IPv4 packet: %v", err)
		return
	}

	fmt.Println("len(pv4Packet) => ", len(pv4Packet))

	var buf bytes.Buffer
	buf.Write(handshakePacket)
	buf.Write(pv4Packet)
	additionalData := make([]byte, 4)
	buf.Write(additionalData)

	fmt.Println("vpnIP => ", vpnIP)

	// 获取远程地址列表
	remoteAddrList := hc.mainHostMap.GetRemoteAddrList(vpnIP)

	fmt.Println("remoteAddrList => ", remoteAddrList)

	// 转换为 net.Addr 类型的地址列表
	var netRemoteAddrList []net.Addr

	// 发送握手消息到远程地址列表中的每个地址
	for _, remoteAddr := range remoteAddrList {
		fmt.Println("handshakePacket => ", buf.Bytes())
		if err := hc.outside.WriteTo(buf.Bytes(), remoteAddr); err != nil {
			hc.logger.Errorf("failed to send handshake packet to %s: %v", remoteAddr, err)
			continue
		}
		hc.logger.
			WithField("vpnIP", vpnIP).
			WithField("addr", remoteAddr).
			WithField("localIndex", hc.localIndexID).
			//WithField("counter", handshakeHostInfo.Counter).
			Info("sent handshake packet")
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

// handleOutboundTimerTick 处理传出握手消息的定时器触发
func (hc *HandshakeController) handleOutboundTimerTick() {
	hc.Lock()
	defer hc.Unlock()

	for vpnIP := range hc.hosts {
		select {
		case hc.outboundTrigger <- vpnIP:
		default:
		}
	}
	hc.outboundTimer.Reset(hc.config.TryInterval)
}

// deleteHandshakeInfo 删除指定 VPN IP 的握手信息
func (hc *HandshakeController) deleteHandshakeInfo(vpnIP api.VpnIp) {
	delete(hc.hosts, vpnIP)
}

// generateHandshakePacket 生成握手消息
func generateHandshakePacket(localIndexID uint32) ([]byte, error) {
	return header.BuildHandshakePacket(localIndexID, 0)
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
