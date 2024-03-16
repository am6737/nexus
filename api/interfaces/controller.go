package interfaces

// OutboundController 出站控制器接口
type OutboundController interface {
	Send(data []byte, destAddr string) error
	Listen()
}

// InboundController 入站控制器接口
type InboundController interface {
	Receive(srcAddr string) ([]byte, error)
	Listen()
}

// HandshakeController 握手控制器接口
type HandshakeController interface {
	Handshake() error
}
