package host

import (
	"encoding/json"
	"fmt"
	"github.com/am6737/nexus/api"
	"github.com/am6737/nexus/transport/protocol/udp"
	"github.com/am6737/nexus/transport/protocol/udp/header"
	"github.com/flynn/noise"
	"github.com/sirupsen/logrus"
	"net"
	"sync"
	"sync/atomic"
)

type CachedPacket struct {
	messageType    header.MessageType
	messageSubType header.MessageSubType
	callback       packetCallback
	packet         []byte
}

type packetCallback func(t header.MessageType, st header.MessageSubType, h *HostInfo, p, nb, out []byte)

func NewHostMap(logger *logrus.Logger, vpnCIDR *net.IPNet, preferredRanges []*net.IPNet) *HostMap {
	h := map[api.VpnIP]*HostInfo{}
	i := map[uint32]*HostInfo{}
	r := map[uint32]*HostInfo{}
	relays := map[uint32]*HostInfo{}
	m := HostMap{
		Indexes:       i,
		Relays:        relays,
		RemoteIndexes: r,
		hosts:         h,
		//preferredRanges: preferredRanges,
		vpnCIDR: vpnCIDR,
		logger:  logger,
	}
	return &m
}

type HostMap struct {
	sync.RWMutex  //Because we concurrently read and write to our maps
	Indexes       map[uint32]*HostInfo
	Relays        map[uint32]*HostInfo // Maps a Relay IDX to a Relay HostInfo object
	RemoteIndexes map[uint32]*HostInfo
	hosts         map[api.VpnIP]*HostInfo
	logger        *logrus.Logger

	preferredRanges []*net.IPNet
	vpnCIDR         *net.IPNet
	metricsEnabled  bool
}

func (hm *HostMap) PrintHosts() {
	hm.RLock()
	defer hm.RUnlock()
	for vpnIP, hostInfo := range hm.hosts {
		fmt.Printf(" vip: %s, remote: %v\n", vpnIP, hostInfo.Remote)
	}
}

func (hm *HostMap) DeleteHost(vip api.VpnIP) {
	hm.Lock()
	defer hm.Unlock()
	delete(hm.hosts, vip)
}

func (hm *HostMap) UpdateHost(vip api.VpnIP, udpAddr *udp.Addr) {
	hm.Lock()
	defer hm.Unlock()
	if hostInfo, ok := hm.hosts[vip]; ok {
		hostInfo.Remote = &udp.Addr{
			IP:   udpAddr.IP,
			Port: uint16(udpAddr.Port),
		}
	} else {
		hm.hosts[vip] = &HostInfo{
			Remote: &udp.Addr{
				IP:   udpAddr.IP,
				Port: uint16(udpAddr.Port),
			},
			Remotes: RemoteList{},
			VpnIp:   vip,
		}
	}
}

func (hm *HostMap) AddHost(vpnIP api.VpnIP, udpAddr *udp.Addr, publicKey []byte) {
	hm.Lock()
	defer hm.Unlock()

	newAddr := udpAddr.Copy()

	hm.logger.WithFields(logrus.Fields{
		"vpnIP":     vpnIP,
		"addr":      newAddr,
		"publicKey": string(publicKey),
	}).Info("Add new host")

	host, ok := hm.hosts[vpnIP]
	if !ok {
		hm.hosts[vpnIP] = &HostInfo{
			Remote:    newAddr,
			VpnIp:     vpnIP,
			PublicKey: publicKey,
		}
		return
	}
	host.Remote = udpAddr
	host.PublicKey = publicKey

	//if host.Remote == nil {
	//	host.Remote = newAddr
	//} else {
	//	if host.Remote.IP.String() != newAddr.IP.String() || host.Remote.Port != newAddr.Port {
	//		hm.logger.WithFields(logrus.Fields{
	//			"vpnIP":    vpnIP,
	//			"old addr": host.Remote,
	//			"new addr": newAddr,
	//		}).Info("Update host addr")
	//		host.Remote = newAddr
	//	}
	//}
}

func (hm *HostMap) QueryVpnIp(vpnIp api.VpnIP) *HostInfo {
	//return hm.queryVpnIp(vpnIp, nil)
	return hm.queryVpnIp(vpnIp)
}

func (hm *HostMap) GetVpnIpPublicKey(vpnIp api.VpnIP) ([]byte, error) {
	h := hm.queryVpnIp(vpnIp)
	if h == nil || h.PublicKey == nil {
		return nil, fmt.Errorf("host not found")
	}
	return h.PublicKey, nil
}

func (hm *HostMap) queryVpnIp(vpnIp api.VpnIP) *HostInfo {
	hm.RLock()
	if h, ok := hm.hosts[vpnIp]; ok {
		hm.RUnlock()
		// Do not attempt promotion if you are a lighthouse
		//if promoteIfce != nil && !promoteIfce.lightHouse.amLighthouse {
		//	h.TryPromoteBest(hm.preferredRanges, promoteIfce)
		//}
		return h

	}

	hm.RUnlock()
	return nil
}

func (hm *HostMap) GetAllHostMap() map[api.VpnIP]*HostInfo {
	hm.RLock()
	defer hm.RUnlock()
	hosts := make(map[api.VpnIP]*HostInfo)
	for vpnIP, hostInfo := range hm.hosts {
		hosts[vpnIP] = hostInfo
	}
	return hosts
}

// GetRemoteAddrList 返回指定 VPN IP 的主机的远程地址列表
func (hm *HostMap) GetRemoteAddrList(vpnIP api.VpnIP) []*udp.Addr {
	hm.RLock()
	defer hm.RUnlock()

	if hostInfo, ok := hm.hosts[vpnIP]; ok {
		return hostInfo.GetRemoteAddrList()
	}

	return nil
}

// GetRemoteAddrList 返回主机的远程地址列表
func (h *HostInfo) GetRemoteAddrList() []*udp.Addr {
	h.Remotes.RLock()
	defer h.Remotes.RUnlock()

	// 检查主机是否有单个远程地址
	if h.Remote != nil {
		return []*udp.Addr{h.Remote}
	}

	// 返回 RemoteList 中的地址列表
	return h.Remotes.addrs
}

type HostInfo struct {
	PublicKey     []byte
	Remote        *udp.Addr
	Remotes       RemoteList
	RemoteIndexId uint32
	LocalIndexId  uint32
	VpnIp         api.VpnIP
}

func (h *HostInfo) String() string {
	marshal, err := json.Marshal(h)
	if err != nil {
		return ""
	}
	return string(marshal)
}

// RemoteList is a unifying concept for lighthouse servers and clients as well as hostinfos.
// It serves as a local cache of query replies, host update notifications, and locally learned addresses
type RemoteList struct {
	// Every interaction with internals requires a lock!
	sync.RWMutex

	// A deduplicated set of addresses. Any accessor should lock beforehand.
	addrs []*udp.Addr
}

type ConnectionState struct {
	//eKey           *CipherState
	//dKey           *CipherState
	H              *noise.HandshakeState
	initiator      bool
	messageCounter atomic.Uint64
	//window         *Bits
	writeLock sync.Mutex
}
