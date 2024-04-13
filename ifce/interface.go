package ifce

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/am6737/nexus/api"
	"github.com/am6737/nexus/host"
	"github.com/am6737/nexus/transport/packet"
	"github.com/am6737/nexus/transport/protocol/udp"
	"github.com/am6737/nexus/transport/protocol/udp/header"
	"github.com/am6737/nexus/tun"
	"github.com/am6737/nexus/utils"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"golang.org/x/net/ipv4"
	"io"
	"net"
	"os"
	"runtime"
	"sync/atomic"
)

const mtu = 1500

const (
	minPacketLen = 4
)

type Interface struct {
	Hosts   map[api.VpnIP]*host.HostInfo
	Conns   map[api.VpnIP]udp.Conn
	outside udp.Conn
	inside  tun.Device

	Writers []udp.Conn
	readers []io.ReadWriteCloser

	cipher string

	routines int

	logger *logrus.Logger

	closed atomic.Bool

	localVpnIP api.VpnIP
}

func (itf *Interface) NewInterface(ctx context.Context, outside udp.Conn, inside tun.Device, routines int, cipher string, logger *logrus.Logger, localVpnIP api.VpnIP) (*Interface, error) {
	return &Interface{
		outside:    outside,
		inside:     inside,
		routines:   routines,
		Hosts:      make(map[api.VpnIP]*host.HostInfo),
		Conns:      make(map[api.VpnIP]udp.Conn, routines),
		Writers:    make([]udp.Conn, routines),
		readers:    make([]io.ReadWriteCloser, routines),
		cipher:     cipher,
		logger:     logger,
		localVpnIP: localVpnIP,
	}, nil
}

func (itf *Interface) Close() error {
	//itf.closed.Store(true)

	for _, u := range itf.Writers {
		err := u.Close()
		if err != nil {
			itf.logger.WithError(err).Error("Error while closing udp socket")
		}
	}

	// Release the tun device
	return itf.inside.Close()
}

func (itf *Interface) Up() {
	addr, err := itf.outside.LocalAddr()
	if err != nil {
		itf.logger.WithError(err).Error("Failed to get udp listen address")
	}

	itf.logger.WithField("interface", itf.inside.Name()).
		WithField("network", itf.inside.Cidr().String()).
		//WithField("build", itf.version).
		WithField("udpAddr", addr).
		//WithField("boringcrypto", boringEnabled()).
		Info("nexus interface is up")

	// Prepare n tun queues
	var reader io.ReadWriteCloser = itf.inside
	for i := 0; i < itf.routines; i++ {
		if i > 0 {
			//reader, err = itf.inside.NewMultiQueueReader()
			//if err != nil {
			//	itf.logger.Fatal(err)
			//}
		}
		itf.readers[i] = reader
	}

	if err := itf.inside.Up(); err != nil {
		if err := itf.inside.Close(); err != nil {
			itf.logger.WithError(err).Error("Failed to up tun device")
		}
		itf.logger.Fatal(err)
	}
}

func (itf *Interface) Run() {
	// Launch n queues to read packets from udp
	for i := 0; i < itf.routines; i++ {
		go itf.listenOut(i)
	}

	// Launch n queues to read packets from tun dev
	for i := 0; i < itf.routines; i++ {
		go itf.listenIn(itf.readers[i], i)
	}
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

	return []byte(ipBytes)
}

func replaceAddresses(out []byte, localIP api.VpnIP, remoteIP api.VpnIP) {
	copy(out[12:16], parseIP(localIP.String()))  // 将本地IP地址替换到目标IP地址的位置
	copy(out[16:20], parseIP(remoteIP.String())) // 将目标IP地址替换到源IP地址的位置
}

func (itf *Interface) listenOut(i int) {
	runtime.LockOSThread()

	var li udp.Conn
	// TODO clean this up with a coherent interface for each outside connection
	if i > 0 {
		li = itf.Writers[i]
	} else {
		li = itf.outside
	}

	li.ListenOut(func(addr *udp.Addr, out []byte, p []byte, h *header.Header) {
		itf.logger.WithField("interface", itf.inside.Name()).
			WithField("udpAddr", addr).
			WithField("out", out).
			WithField("packet", p).
			Info("接收到远程数据包")

		out = p
		pk := &packet.Packet{}
		if err := utils.ParsePacket(p, false, pk); err != nil {
			itf.logger.Error(err)
			return
		}

		itf.logger.WithField("pkLocalIP", pk.LocalIP).
			WithField("pkRemoteIP", pk.RemoteIP).
			WithField("localVpnIP", itf.localVpnIP.String()).
			WithField("pkLocalPort", pk.LocalPort).
			Info("Packet info")

		// 判断是否是自己的数据包
		if pk.LocalIP.String() == itf.localVpnIP.String() {
			replaceAddresses(out, pk.RemoteIP, pk.LocalIP)
			if _, err := itf.readers[i].Write(out); err != nil {
				itf.logger.WithError(err).Error("Failed to forward to tun")
			}
			return
		}

		//if host, ok := itf.Hosts[pk.LocalIP]; ok {
		if err := itf.Writers[i].WriteTo(out, addr); err != nil {
			itf.logger.WithError(err).Error("Failed to write to conn")
		}
		//}
	})
}

func (itf *Interface) listenIn(reader io.ReadWriteCloser, i int) {
	runtime.LockOSThread()

	p := &packet.Packet{}
	packet := make([]byte, mtu)
	out := make([]byte, mtu)
	nb := make([]byte, 12, 12)

	for {
		n, err := reader.Read(packet)
		if err != nil {
			if errors.Is(err, os.ErrClosed) && itf.closed.Load() {
				return
			}
			itf.logger.WithError(err).Error("Error while reading outbound packet")
			// This only seems to happen when something fatal happens to the fd, so exit.
			os.Exit(2)
		}
		itf.consumeInsidePacket(packet[:n], p, nb, out, i)
	}
}

type VpnIp uint32

// PacketInfo 结构体用于存储解析后的数据包信息
type PacketInfo struct {
	Version        uint8
	HeaderLength   uint8
	TotalLength    uint16
	TTL            uint8
	Protocol       uint8
	Identification uint16
	Flags          uint8
	FragmentOffset uint16
	DestinationIP  net.IP
	SourceIP       net.IP
}

// ParsePacket 函数用于解析数据包并返回解析后的信息
func ParsePacket(data []byte, incoming bool, p *packet.Packet) error {
	// Do we at least have an ipv4 header worth of data?
	if len(data) < ipv4.HeaderLen {
		return fmt.Errorf("packet is less than %v bytes", ipv4.HeaderLen)
	}

	// Is it an ipv4 packet?
	if int((data[0]>>4)&0x0f) != 4 {
		return fmt.Errorf("packet is not ipv4, type: %v", int((data[0]>>4)&0x0f))
	}

	// Adjust our start position based on the advertised ip header length
	ihl := int(data[0]&0x0f) << 2

	// Well formed ip header length?
	if ihl < ipv4.HeaderLen {
		return fmt.Errorf("packet had an invalid header length: %v", ihl)
	}

	// Check if this is the second or further fragment of a fragmented packet.
	flagsfrags := binary.BigEndian.Uint16(data[6:8])
	p.Fragment = (flagsfrags & 0x1FFF) != 0

	// Firewall handles protocol checks
	p.Protocol = data[9]

	// Accounting for a variable header length, do we have enough data for our src/dst tuples?
	minLen := ihl
	if !p.Fragment && p.Protocol != packet.ProtoICMP {
		minLen += minPacketLen
	}
	if len(data) < minLen {
		return fmt.Errorf("packet is less than %v bytes, ip header len: %v", minLen, ihl)
	}

	// Firewall packets are locally oriented
	if incoming {
		p.RemoteIP = api.Ip2VpnIp(data[12:16])
		p.LocalIP = api.Ip2VpnIp(data[16:20])
		if p.Fragment || p.Protocol == packet.ProtoICMP {
			p.RemotePort = 0
			p.LocalPort = 0
		} else {
			p.RemotePort = binary.BigEndian.Uint16(data[ihl : ihl+2])
			p.LocalPort = binary.BigEndian.Uint16(data[ihl+2 : ihl+4])
		}
	} else {
		p.LocalIP = api.Ip2VpnIp(data[12:16])
		p.RemoteIP = api.Ip2VpnIp(data[16:20])
		if p.Fragment || p.Protocol == packet.ProtoICMP {
			p.RemotePort = 0
			p.LocalPort = 0
		} else {
			p.LocalPort = binary.BigEndian.Uint16(data[ihl : ihl+2])
			p.RemotePort = binary.BigEndian.Uint16(data[ihl+2 : ihl+4])
		}
	}

	return nil
}

func (itf *Interface) consumeInsidePacket(data []byte, packet *packet.Packet, nb []byte, out []byte, q int) {
	if err := ParsePacket(data, false, packet); err != nil {
		itf.logger.WithField("packet", packet).
			WithField("data", data).
			WithError(err).Error("Error while validating outbound packet")
		return
	}

	if packet.RemoteIP == itf.localVpnIP {
		// Immediately forward packets from self to self.
		// This should only happen on Darwin-based and FreeBSD hosts, which
		// routes packets from the Nebula IP to the Nebula IP through the Nebula
		// TUN device.
		//fmt.Println("immediatelyForwardToSelf => ", ImmediatelyForwardToSelf)
		if ImmediatelyForwardToSelf {
			_, err := itf.readers[q].Write(data)
			if err != nil {
				itf.logger.WithError(err).Error("Failed to forward to tun")
			}
		}
		// Otherwise, drop. On linux, we should never see these packets - Linux
		// routes packets from the nebula IP to the nebula IP through the loopback device.
		return
	}

	host, ok := itf.Hosts[packet.RemoteIP]
	if !ok {
		itf.logger.WithField("remoteIp", packet.RemoteIP).Warn("Host not found")
		return
	}
	if host.VpnIp != packet.RemoteIP {
		itf.logger.WithField("remoteIp", packet.RemoteIP).Warn("Host not found")
		return
	}

	itf.logger.WithField("remoteIp", host.Remote.IP).
		WithField("remotePort", host.Remote.Port).
		WithField("data", data).
		Info("consume packet forward to udp")

	if err := itf.Writers[q].WriteTo(data, host.Remote); err != nil {
		itf.logger.WithError(err).Error("Failed to forward to udp")
	}
}
