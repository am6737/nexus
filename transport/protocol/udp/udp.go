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
