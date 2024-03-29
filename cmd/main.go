package main

import (
	"flag"
	"github.com/am6737/nexus/config"
	"github.com/am6737/nexus/controllers"
	"github.com/am6737/nexus/tun"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"os"
)

var (
	configFile string
)

func init() {
	flag.StringVar(&configFile, "config", "", "Configuration file path.")
	flag.Parse()
}

func main() {
	cfg, err := config.Load(configFile)
	if err != nil {
		panic(err)
	}

	logger := logrus.New()
	logger.Out = os.Stdout

	// 创建新的 DarwinTun 实例
	tunDevice, err := tun.NewDeviceFromConfig(cfg, nil)
	if err != nil {
		logger.WithError(err).Error("Error creating DarwinTun")
		return
	}
	defer tunDevice.Close()

	ctx := context.Background()

	ctrl := controllers.NewControllersManager(cfg, logger, tunDevice)
	if err := ctrl.Start(ctx); err != nil {
		panic(err)
	}
	ctrl.Shutdown()
}
