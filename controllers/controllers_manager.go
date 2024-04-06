package controllers

import (
	"fmt"
	"github.com/am6737/nexus/api"
	"github.com/am6737/nexus/api/interfaces"
	"github.com/am6737/nexus/config"
	"github.com/am6737/nexus/host"
	"github.com/am6737/nexus/transport/protocol/udp"
	"github.com/am6737/nexus/tun"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
)

type ControllersManager struct {
	logger *logrus.Logger

	hostMap        *host.HostMap
	internalWriter io.Writer

	Handshake interfaces.HandshakeController
	Inbound   interfaces.InboundController
	Outbound  interfaces.OutboundController
}

func NewControllersManager(config *config.Config, logger *logrus.Logger, tun tun.Device) *ControllersManager {
	localVpnIP := api.Ip2VpnIp(tun.Cidr().IP)

	// Initialize inbound controller
	inboundLogger := logger.WithField("controller", "Inbound")
	inboundController := &InboundController{
		cfg:        config,
		mtu:        tun.MTU(),
		localVpnIP: localVpnIP,
		inside:     tun,
		logger:     inboundLogger.Logger,
	}

	// Initialize outbound controller
	outboundLogger := logger.WithField("controller", "Outbound")
	outboundController := &OutboundController{
		localVpnIP: localVpnIP,
		logger:     outboundLogger.Logger,
		cfg:        config,
		remotes:    make(map[api.VpnIp]*host.HostInfo),
	}

	lighthouses := map[api.VpnIp]*host.HostInfo{}
	for _, ip := range config.Lighthouse.Hosts {
		if addr, ok := config.StaticHostMap[ip]; ok {
			udpAddr, err := net.ResolveUDPAddr("udp", addr[0])
			if err != nil {
				fmt.Println("解析地址出错：", err)
				continue
			}
			vpnIp, err := api.ParseVpnIp(ip)
			if err != nil {
				fmt.Println("解析地址出错：", err)
				continue
			}
			lighthouses[vpnIp] = &host.HostInfo{
				Remote: &udp.Addr{
					IP:   udpAddr.IP,
					Port: uint16(udpAddr.Port),
				},
			}
		}
	}

	handshakeController := &HandshakeController{
		localVpnIP: localVpnIP,
		sendFunc: func(out []byte, addr *udp.Addr) error {
			return outboundController.SendToRemote(out, addr)
		},
		mtu:            tun.MTU(),
		lighthouses:    lighthouses,
		hosts:          make(map[api.VpnIp]*host.HostInfo),
		handshakeQueue: make(chan udp.Addr),
		logger:         logger.WithField("controller", "Handshake").Logger,
	}

	// Initialize controllers manager
	controllersManager := &ControllersManager{
		logger:         logger,
		internalWriter: tun,
		Handshake:      handshakeController,
		Inbound:        inboundController,
		Outbound:       outboundController,
	}

	return controllersManager
}

func (c *ControllersManager) Start(ctx context.Context) error {
	if err := c.Inbound.Start(ctx); err != nil {
		return err
	}

	if err := c.Outbound.Start(ctx); err != nil {
		return err
	}

	if err := c.Handshake.Start(ctx); err != nil {
		return err
	}

	go c.Inbound.Listen(func(out []byte, addr string) error {
		return c.Outbound.Send(out, addr)
	})

	go c.Outbound.Listen(c.internalWriter)

	return nil
}

// Stop signals nebula to shutdown and close all tunnels, returns after the shutdown is complete
func (c *ControllersManager) Stop() {
	if err := c.Outbound.Close(); err != nil {
		c.logger.WithField("error", err).Error("Failed to close outbound controller")
	}
	if err := c.Inbound.Close(); err != nil {
		c.logger.WithField("error", err).Error("Failed to close inbound controller")
	}
	c.logger.Info("Goodbye")
}

func (c *ControllersManager) Shutdown() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM)
	signal.Notify(sigChan, syscall.SIGINT)

	rawSig := <-sigChan
	sig := rawSig.String()
	c.logger.WithField("signal", sig).Info("Caught signal, shutting down")
	c.Stop()
}
