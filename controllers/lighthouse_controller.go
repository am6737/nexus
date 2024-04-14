package controllers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/am6737/nexus/api"
	"github.com/am6737/nexus/api/interfaces"
	"github.com/am6737/nexus/host"
	"github.com/am6737/nexus/transport/packet"
	"github.com/am6737/nexus/transport/protocol/udp"
	"github.com/am6737/nexus/transport/protocol/udp/header"
	"github.com/sirupsen/logrus"
	"log"
	"sync"
	"time"
)

var (
	QueryTimeout   = 2 * time.Second
	UpdateInterval = 30 * time.Second
)

var _ interfaces.LighthouseController = &LighthouseController{}

func NewLighthouseController(logger *logrus.Logger, host *host.HostMap, ow interfaces.OutsideWriter, isLighthouse bool, localVpnIP api.VpnIP) *LighthouseController {
	return &LighthouseController{
		logger:       logger,
		host:         host,
		ow:           ow,
		isLighthouse: isLighthouse,
		localVpnIP:   localVpnIP,
		//handshakeHosts:       make(map[api.VpnIP]*host.HostInfo),
		queryQueue:  make(chan api.VpnIP, 1000),
		queryWorker: &sync.WaitGroup{},
	}
}

type LighthouseController struct {
	mu   sync.RWMutex
	host *host.HostMap
	//handshakeHosts       map[api.VpnIP]*host.HostInfo
	queryQueue  chan api.VpnIP
	queryWorker *sync.WaitGroup
	logger      *logrus.Logger
	localVpnIP  api.VpnIP

	ow interfaces.OutsideWriter

	isLighthouse bool
}

func (lc *LighthouseController) IsLighthouse() bool {
	return lc.isLighthouse
}

func (lc *LighthouseController) HandleRequest(rAddr *udp.Addr, pk *packet.Packet, h *header.Header, p []byte) {
	switch h.MessageSubtype {
	case header.HostSync:
		lc.handleHostSync(rAddr, pk)
	case header.HostSyncReply:
		lc.handleHostSyncReply(rAddr, pk, p)
	case header.HostQuery:
		lc.handleHostQuery(nil, pk.RemoteIP, rAddr)
	case header.HostQueryReply:
		lc.handleHostQueryReply(pk.RemoteIP, p)
	case header.HostUpdateNotification:
	//lc.handleHostUpdateNotification(n, vpnIp)
	case header.HostPunch:
		lc.handleHostPunch(rAddr, pk.RemoteIP, p)
	}
}

func (lc *LighthouseController) handleHostQuery(n interface{}, ip api.VpnIP, addr *udp.Addr) {
	host, err := lc.Query(ip)
	if err != nil {
		lc.logger.
			WithField("vpnIp", ip).
			WithError(err).
			Warn("LighthouseController handleHostQuery")
		return
	}
	var buf bytes.Buffer
	h := header.BuildHostQueryReply(host.LocalIndexId, 0)
	buf.Write(h)
	b, err := json.Marshal(host)
	if err != nil {
		return
	}
	buf.Write(b)
	lc.logger.
		WithField("vpnIp", ip).
		WithField("addr", addr).
		Info("收到节点查询请求")
	lc.logger.
		WithField("vpnIp", ip).
		WithField("p", buf.Bytes()).
		WithField("addr", host.Remote.NetAddr()).
		Info("发送节点查询结果")
	lc.ow.WriteToAddr(buf.Bytes(), host.Remote.NetAddr())
}

func (lc *LighthouseController) handleHostQueryReply(ip api.VpnIP, p []byte) {
	hi := &host.HostInfo{}
	if err := json.Unmarshal(p, hi); err != nil {
		lc.logger.WithError(err).Error("LighthouseController handleHostQueryReply")
		return
	}
	lc.logger.
		WithField("vpnIp", ip).
		WithField("host", hi).
		Info("收到节点查询回复")
	//lc.Store(hi)
}

func (lc *LighthouseController) Start(ctx context.Context) error {
	lc.logger.Info("Starting lighthouse controller")
	// 启动定时任务，定期发送节点更新通知
	go lc.startUpdateWorker(ctx)
	// 启动查询处理工作人员
	go lc.startQueryWorker(ctx)
	return nil
}

func (lc *LighthouseController) startUpdateWorker(ctx context.Context) {
	ticker := time.NewTicker(UpdateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			//lc.SendUpdate()
		}
	}
}

func (lc *LighthouseController) startQueryWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case vpnIP := <-lc.queryQueue:
			lc.queryWorker.Add(1)
			go func(vpnIP api.VpnIP) {
				defer lc.queryWorker.Done()
				lc.processQuery(vpnIP)
			}(vpnIP)
		}
	}
}

func (lc *LighthouseController) Query(vpnIP api.VpnIP) (*host.HostInfo, error) {
	host := lc.host.QueryVpnIp(vpnIP)
	if host != nil {
		return host, nil
	}
	lc.queryQueue <- vpnIP
	return nil, errors.New("node not found")
}

func (lc *LighthouseController) processQuery(vpnIP api.VpnIP) {
	// 发送查询消息到其他节点
	//queryMsg := NewQueryMessage(vpnIP)
	//response, err := lc.sendQueryToLighthouses(queryMsg)
	//if err != nil {
	//	log.Printf("Query failed for VPN IP %s: %v\n", vpnIP, err)
	//	return
	//}
	//
	//// 解析响应消息
	//info, err := ParseQueryResponse(response)
	//if err != nil {
	//	log.Printf("Failed to parse query response for VPN IP %s: %v\n", vpnIP, err)
	//	return
	//}
	//
	//// 存储查询结果
	//if err := lc.Store(info); err != nil {
	//	log.Printf("Failed to store query response for VPN IP %s: %v\n", vpnIP, err)
	//}
}

func (lc *LighthouseController) Store(info *host.HostInfo) error {
	if info == nil {
		return errors.New("nil node info")
	}

	lc.mu.Lock()
	defer lc.mu.Unlock()

	//lc.host.UpdateHost(info.VpnIP, info.Remote)
	log.Printf("Node stored successfully: %+v\n", info)
	return nil
}

func (lc *LighthouseController) handleHostPunch(addr *udp.Addr, vpnIP api.VpnIP, p []byte) {
	lc.logger.
		WithField("vpnIp", vpnIP).
		WithField("addr", addr).
		Info("打洞请求")
	empty := []byte{0}

	// 执行单次打洞的函数
	punch := func(vpnPeer *udp.Addr) {
		if vpnPeer == nil {
			return
		}

		go func() {
			// 可选：根据需要设置打洞操作的延迟
			time.Sleep(time.Second)

			// 发送打洞数据包
			err := lc.ow.WriteToAddr(empty, vpnPeer.NetAddr())
			if err != nil {
				lc.logger.WithError(err).Error("Failed to send punch packet")
			} else {
				lc.logger.Debugf("Punching on %d for %s", vpnPeer.Port, vpnIP)
			}
		}()
	}

	// 可以根据具体情况获取要进行打洞的地址列表
	// 这里假设你有一个名为 getPeerAddrs 的函数用于获取对端地址列表
	//peerAddrs := getPeerAddrs(vpnIp)
	//
	//// 遍历地址列表执行打洞操作
	//for _, peerAddr := range peerAddrs {
	//	punch(peerAddr)
	//}

	punch(addr)
}

func (lc *LighthouseController) handleHostSync(addr *udp.Addr, pk *packet.Packet) {
	lc.logger.
		WithField("remoteIP", pk.RemoteIP).
		WithField("addr", addr).
		Info("收到主机同步请求")
	lc.host.UpdateHost(pk.RemoteIP, addr)
	if len(lc.host.GetAllHostMap()) <= 0 {
		return
	}
	hp, _ := json.Marshal(lc.host.GetAllHostMap())
	replyPacket, err := lc.buildHandshakeHostSyncReplyPacket(pk.RemoteIP, hp)
	if err != nil {
		lc.logger.WithError(err).Error("构建握手数据包出错")
		return
	}
	lc.logger.
		WithField("remoteIP", pk.RemoteIP).
		WithField("addr", addr).
		WithField("pk", pk).
		Info("发送主机同步回复数据包")
	if err := lc.ow.WriteToAddr(replyPacket, addr); err != nil {
		lc.logger.WithError(err).Error("数据转发到远程")
	}
}

func (lc *LighthouseController) handleHostSyncReply(addr *udp.Addr, pk *packet.Packet, p []byte) {
	if lc.IsLighthouse() {
		return
	}

	lc.logger.
		WithField("remoteIP", pk.RemoteIP).
		WithField("addr", addr).
		WithField("pk", pk).
		Info("收到灯塔同步回复请求")
	p = p[header.Len+20:]
	var hs map[api.VpnIP]*host.HostInfo
	if err := json.Unmarshal(p, &hs); err != nil {
		lc.logger.WithError(err).Error("解析数据包出错")
		return
	}

	for i, i2 := range hs {
		if i == lc.localVpnIP {
			continue
		}
		lc.logger.
			WithField("remoteIP", i).
			WithField("addr", i2.Remote).
			Info("收到的同步地址信息")
		punchPacket, err := lc.buildHandshakeHostRequestPacket(i)
		if err != nil {
			lc.logger.WithError(err).Error("buildTestPacket")
			return
		}
		lc.logger.
			WithField("remoteIP", i).
			WithField("addr", i2.Remote).
			Debug("发送握手消息")
		if err := lc.ow.WriteToAddr(punchPacket, i2.Remote); err != nil {
			lc.logger.WithError(err).Error("数据转发到远程")
		}
		lc.host.UpdateHost(i, i2.Remote)
	}
}

func (lc *LighthouseController) buildHandshakeHostRequestPacket(vip api.VpnIP) ([]byte, error) {
	return lc.buildHandshakePacket(vip, header.HostHandshakeRequest)
}

func (lc *LighthouseController) buildHandshakeHostSyncReplyPacket(vip api.VpnIP, data []byte) ([]byte, error) {
	handshakePacket, err := header.BuildHandshake(0, header.HostSyncReply, 0)
	if err != nil {
		return nil, err
	}
	pv4Packet, err := packet.BuildIPv4Packet(lc.localVpnIP.ToIP(), vip.ToIP(), packet.ProtoUDP, false)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	buf.Write(handshakePacket)
	buf.Write(pv4Packet)
	//if len(data) < 4 {
	//	data = make([]byte, 4)
	//}
	buf.Write(data)
	return buf.Bytes(), nil
}

func (lc *LighthouseController) buildHandshakePacket(vip api.VpnIP, ms header.MessageSubType) ([]byte, error) {
	h, err := header.BuildHandshake(0, ms, 0)
	if err != nil {
		return nil, err
	}
	pk, err := packet.BuildIPv4Packet(lc.localVpnIP.ToIP(), vip.ToIP(), packet.ProtoUDP, false)
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
