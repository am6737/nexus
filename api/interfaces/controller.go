package interfaces

import (
	"context"
	"github.com/am6737/nexus/api"
	"github.com/am6737/nexus/host"
	"github.com/am6737/nexus/transport/protocol/udp"
	"io"
)

type Runnable interface {
	// Start starts running the component.  The component will stop running
	// when the context is closed. Start blocks until the context is closed or
	// an error occurs.
	Start(context.Context) error
}

// SendToRemote 定义一个发送数据到远程地址的函数类型
//type SendToRemote func(b []byte, remoteAddr *udp.Addr) error

// OutboundController 出站控制器接口
type OutboundController interface {
	Runnable
	Listen(internalWriter io.Writer)
	Send(out []byte, vip api.VpnIp) error
	SendToRemote(out []byte, addr *udp.Addr) error
	Close() error
}

// InboundController 入站控制器接口
type InboundController interface {
	Runnable
	Listen(outbound func(out []byte, ip api.VpnIp) error)
	Send(p []byte) (n int, err error)
	Close() error
}

// HandshakeController 握手控制器接口
type HandshakeController interface {
	Runnable
	Handshake(vpnIp api.VpnIp) error
}

// LighthouseController 灯塔控制器接口
type LighthouseController interface {
	Runnable
	// Query 查询指定VPN IP地址的节点信息
	Query(vpnIP api.VpnIp) (*host.HostInfo, error)
	// Store 存储节点信息
	Store(info *host.HostInfo) error
}
