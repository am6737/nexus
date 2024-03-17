package interfaces

import (
	"context"
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
	//Listen(internalWriter func(p []byte) (n int, err error))
	Listen(internalWriter io.Writer)
	Send(out []byte, addr string) error
	Close() error
}

// InboundController 入站控制器接口
type InboundController interface {
	Runnable
	Listen(outbound func(out []byte, addr string) error)
	Send(p []byte) (n int, err error)
	Close() error
}

// HandshakeController 握手控制器接口
type HandshakeController interface {
	Handshake() error
}
