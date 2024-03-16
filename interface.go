package nexus

import "golang.org/x/net/context"

// Communicator 定义了通用的网络通信接口
type Communicator interface {
	Start(ctx context.Context) error
	ConnToTun()
	TunToConn()
	Close() error
}
