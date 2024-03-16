package tun

import (
	"errors"
	"fmt"
	"github.com/am6737/nexus/config"
	"github.com/sirupsen/logrus"
	"net"
)

type DeviceFactory func(c *config.Config, l *logrus.Logger, tunCidr *net.IPNet) (Device, error)

func NewDeviceFromConfig(c *config.Config, l *logrus.Logger) (Device, error) {
	tunCidr, err := parseIPNet(c.Tun.IP, c.Tun.Mask)
	if err != nil {
		return nil, err
	}

	fmt.Println("tunCidr => ", tunCidr)

	switch {
	case c.Tun.Disabled:
		//tun := newDisabledTun(tunCidr, c.GetInt("tun.tx_queue", 500), c.GetBool("stats.message_metrics", false), l)
		return nil, errors.New("tun disabled")

	default:
		return newTun(
			c.Tun.Dev,
			tunCidr,
			c.Tun.MTU,
			500,
			false,
		)
	}
}

func parseIPNet(ipAddress, subnetMask string) (*net.IPNet, error) {
	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipAddress)
	}

	mask := net.ParseIP(subnetMask)
	if mask == nil {
		return nil, fmt.Errorf("invalid subnet mask: %s", subnetMask)
	}

	// Convert mask to IPMask type
	ones, _ := mask.DefaultMask().Size()
	ipMask := net.CIDRMask(ones, 32)

	// Create IPNet struct
	ipNet := &net.IPNet{
		IP:   ip,
		Mask: ipMask,
	}
	return ipNet, nil
}
