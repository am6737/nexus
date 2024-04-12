package udp

import (
	"fmt"
	"net"
)

type Addr struct {
	IP   net.IP
	Port uint16
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
	return &Addr{
		IP:   a.IP.To4(),
		Port: a.Port,
	}
}
