package controllers

import (
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

	internalWriter io.Writer
	Inbound        interfaces.InboundController
	Outbound       interfaces.OutboundController
}

func NewControllersManager(config *config.Config, logger *logrus.Logger, tun tun.Device) *ControllersManager {
	localVpnIP := api.Ip2VpnIp(tun.Cidr().IP)

	var (
		err           error
		port          = config.Listen.Port
		listenHost    *net.IPAddr
		rawListenHost = config.Listen.Host
		routines      = 1
		batch         = config.Listen.Batch
		conn          udp.Conn
	)

	if rawListenHost == "[::]" {
		// Old guidance was to provide the literal `[::]` in `listen.host` but that won't resolve.
		listenHost = &net.IPAddr{IP: net.IPv6zero}

	} else {
		listenHost, err = net.ResolveIPAddr("ip", rawListenHost)
		if err != nil {
			//return nil, util.ContextualizeIfNeeded("Failed to resolve listen.host", err)
			panic(err)
		}
	}

	logger.Infof("InboundController listening %q %d", listenHost.IP, port)
	udpServer, err := udp.NewListener(logger, listenHost.IP, port, routines > 1, batch)
	if err != nil {
		//return nil, util.NewContextualError("Failed to open udp listener", m{"queue": i}, err)
		panic(err)
	}
	udpServer.ReloadConfig(config)
	conn = udpServer

	// Initialize inbound controller
	inboundLogger := logger.WithField("controller", "Inbound")
	inboundController := &InboundController{
		cfg:        config,
		mtu:        tun.MTU(),
		localVpnIP: localVpnIP,
		outside:    conn,
		inside:     tun,
		logger:     inboundLogger.Logger,
		remotes:    make(map[api.VpnIp]*host.HostInfo),
	}

	// Initialize outbound controller
	outboundLogger := logger.WithField("controller", "Outbound")
	outboundController := &OutboundController{
		localVpnIP: localVpnIP,
		logger:     outboundLogger.Logger,
		cfg:        config,
		outside:    conn,
		inside:     tun,
		remotes:    make(map[api.VpnIp]*host.HostInfo),
	}

	// Initialize controllers manager
	controllersManager := &ControllersManager{
		logger:         logger,
		internalWriter: tun,
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

	go c.Inbound.Listen(func(out []byte, addr string) error {
		return c.Outbound.Send(out, addr)
	})
	//
	//go c.Outbound.Listen(func(p []byte) (n int, err error) {
	//	return c.Inbound.Send(p)
	//})

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
