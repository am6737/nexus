package main

import (
	"github.com/am6737/nexus/cmd"
	"log"
	"os"
)

//var (
//	configFile string
//)

//func init() {
//	flag.StringVar(&configFile, "config", "/Users/lms/Documents/biset/nexus/config.yaml", "Configuration file path.")
//	flag.Parse()
//}

//func main() {
//	cfg, err := config.Load(configFile)
//	if err != nil {
//		panic(err)
//	}
//
//	logger := logrus.New()
//	logger.Out = os.Stdout
//	logger.SetLevel(logrus.DebugLevel)
//	logger.SetFormatter(&logrus.TextFormatter{
//		TimestampFormat: "2006-01-02 15:04:05",
//		FullTimestamp:   true,
//	})
//
//	// 创建新的 DarwinTun 实例
//	tunDevice, err := tun.NewDeviceFromConfig(cfg, nil)
//	if err != nil {
//		logger.WithError(err).Error("Error creating DarwinTun")
//		return
//	}
//	defer tunDevice.Close()
//
//	ctx := context.Background()
//	ctrl := controllers.NewControllersManager(ctx, cfg, logger, tunDevice)
//	if err := ctrl.Start(ctx); err != nil {
//		panic(err)
//	}
//	ctrl.Shutdown()
//}

func main() {
	err := cmd.App.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
