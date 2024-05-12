package interfaces

import (
	"context"
	"github.com/am6737/nexus/api"
	"github.com/am6737/nexus/host"
	"github.com/am6737/nexus/transport/packet"
	"github.com/am6737/nexus/transport/protocol/udp"
	"github.com/am6737/nexus/transport/protocol/udp/header"
	"io"
	"net"
)

type Runnable interface {
	// Start starts running the component.  The component will stop running
	// when the context is closed. Start blocks until the context is closed or
	// an error occurs.
	Start(context.Context) error
}

type Writer interface {
	OutsideWriter
	InsideWriter
}

type OutsideWriter interface {
	WriteToAddr(p []byte, addr net.Addr) error
	WriteToVIP(p []byte, addr api.VpnIP) error
}

type InsideWriter interface {
	io.Writer
}

// InboundController 入站控制器接口
type InboundController interface {
	Runnable
	OutsideWriter
	Listen(internalWriter InsideWriter)
	//Send(out []byte, vip api.VpnIP) error
	//SendToRemote(out []byte, addr *udp.Addr) error
	Close() error
}

// OutboundController 入站控制器接口
type OutboundController interface {
	Runnable
	Listen(externalWriter OutsideWriter)
	Send(p []byte) (n int, err error)
	Close() error
}

// HandshakeController 握手控制器接口
type HandshakeController interface {
	Runnable
	Handshake(vpnIp api.VpnIP, packet []byte) error
	HandleRequest(rAddr *udp.Addr, packet *packet.Packet, h *header.Header, p []byte)
}

// LighthouseController 灯塔控制器接口
type LighthouseController interface {
	Runnable
	// Query 查询指定VPN IP地址的节点信息
	Query(vpnIP api.VpnIP) (*host.HostInfo, error)
	// Store 存储节点信息
	Store(info *host.HostInfo) error

	HandleRequest(rAddr *udp.Addr, packet *packet.Packet, h *header.Header, p []byte)

	// IsLighthouse 判断当前节点是否是灯塔节点
	IsLighthouse() bool
}

type NetworkController interface {
	Create(ctx context.Context, cmd *api.CreateNetwork) (*api.CreateNetworkResponse, error)
	Get(ctx context.Context, id string) (*api.Network, error)
	GetAll(ctx context.Context, query *api.QueryNetwork) ([]*api.Network, error)
	Delete(ctx context.Context, id string) error
	Update(ctx context.Context, cmd *api.UpdateNetwork) (*api.Network, error)

	AllocateAutoAddress(ctx context.Context, networkID string) (api.VpnIP, error)
	AllocateStaticAddress(ctx context.Context, networkID string, addr api.VpnIP) (api.VpnIP, error)
	RecycleAddress(ctx context.Context, networkID string, addr api.VpnIP) error
	UsedAddresses(ctx context.Context, networkID string) ([]api.VpnIP, error)
	AvailableAddresses(ctx context.Context, networkID string) ([]api.VpnIP, error)
}

// HostController 定义主机控制器接口
type HostController interface {
	Get(ctx context.Context, id string) (*api.Host, error)
	GetAll(ctx context.Context) ([]*api.Host, error)
	Find(ctx context.Context, query *api.FindOptions) ([]*api.Host, error)
	Create(ctx context.Context, cmd *api.Host) (*api.Host, error)
	Update(ctx context.Context, cmd *api.Host) (*api.Host, error)
	Delete(ctx context.Context, id string) error
}
