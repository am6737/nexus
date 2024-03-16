package controllers

import (
	"github.com/am6737/nexus/ifce"
	"github.com/sirupsen/logrus"
	"os"
	"os/signal"
	"syscall"
)

type ControllersManager struct {
	ifce   *ifce.Interface
	logger *logrus.Logger
}

func NewControllersManager(ifce *ifce.Interface, logger *logrus.Logger) *ControllersManager {
	return &ControllersManager{
		ifce:   ifce,
		logger: logger,
	}
}

func (c *ControllersManager) Start() {
	// Activate the interface
	c.ifce.Up()

	// Start reading packets.
	c.ifce.Run()
}

// Stop signals nebula to shutdown and close all tunnels, returns after the shutdown is complete
func (c *ControllersManager) Stop() {
	// Stop the handshakeManager (and other services), to prevent new tunnels from
	// being created while we're shutting them all down.
	//c.cancel()

	//c.CloseAllTunnels(false)
	if err := c.ifce.Close(); err != nil {
		c.logger.WithError(err).Error("Close interface failed")
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
