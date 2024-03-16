package udp

import (
	"github.com/am6737/nexus/config"
)

const MTU = 9001

type EncReader func(addr *Addr, out []byte, packet []byte)

type Conn interface {
	Rebind() error
	LocalAddr() (*Addr, error)
	ListenOut(r EncReader)
	WriteTo(b []byte, addr *Addr) error
	ReloadConfig(c *config.Config)
	Close() error
}

type NoopConn struct{}

func (n NoopConn) Rebind() error {
	//TODO implement me
	panic("implement me")
}

func (n NoopConn) LocalAddr() (*Addr, error) {
	//TODO implement me
	panic("implement me")
}

func (n NoopConn) ListenOut(r EncReader) {
	//TODO implement me
	panic("implement me")
}

func (n NoopConn) WriteTo(b []byte, addr *Addr) error {
	//TODO implement me
	panic("implement me")
}

func (n NoopConn) ReloadConfig(c *config.Config) {
	//TODO implement me
	panic("implement me")
}

func (n NoopConn) Close() error {
	//TODO implement me
	panic("implement me")
}
