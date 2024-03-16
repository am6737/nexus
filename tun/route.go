package tun

import (
	"github.com/am6737/nexus/api"
	"net"
)

type Route struct {
	MTU     int
	Metric  int
	Cidr    *net.IPNet
	Via     *api.VpnIp
	Install bool
}
