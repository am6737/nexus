package udp

import "net"

type Addr struct {
	IP   net.IP
	Port uint16
}
