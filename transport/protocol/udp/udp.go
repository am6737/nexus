package udp

import (
	"fmt"
	"net"
)

type Addr struct {
	IP   net.IP
	Port uint16
}

func (a Addr) Network() string {
	return "udp"
}

func (a Addr) String() string {
	return fmt.Sprintf("%s:%d", a.IP.String(), a.Port)
}

func (a Addr) NetAddr() net.Addr {
	return &net.UDPAddr{
		IP:   a.IP,
		Port: int(a.Port),
	}
}

func (a Addr) Copy() *Addr {
	newAddr := &Addr{
		IP:   make(net.IP, len(a.IP)),
		Port: a.Port,
	}
	copy(newAddr.IP, a.IP)
	return newAddr
}
