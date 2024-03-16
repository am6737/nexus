package main

import (
	"flag"
	"fmt"
	"github.com/am6737/nexus/api"
	"github.com/am6737/nexus/config"
	"github.com/am6737/nexus/controllers"
	"github.com/am6737/nexus/host"
	"github.com/am6737/nexus/ifce"
	"github.com/am6737/nexus/transport/protocol/udp"
	"github.com/am6737/nexus/tun"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"net"
	"os"
	"time"
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
		return
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

	rawListenHost := cfg.Listen.Host
	var listenHost *net.IPAddr
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

	var routines = 1

	// set up our UDP listener
	udpConns := make([]udp.Conn, routines)
	port := cfg.Listen.Port

	for i := 0; i < routines; i++ {
		logger.Infof("listening %q %d", listenHost.IP, port)
		udpServer, err := udp.NewListener(logger, listenHost.IP, port, routines > 1, cfg.Listen.Batch)
		if err != nil {
			//return nil, util.NewContextualError("Failed to open udp listener", m{"queue": i}, err)
			panic(err)
		}
		udpServer.ReloadConfig(cfg)
		udpConns[i] = udpServer

		// If port is dynamic, discover it before the next pass through the for loop
		// This way all routines will use the same port correctly
		if port == 0 {
			uPort, err := udpServer.LocalAddr()
			if err != nil {
				//return nil, util.NewContextualError("Failed to get listening port", nil, err)
				panic(err)
			}
			port = int(uPort.Port)
		}
	}

	var ifce *ifce.Interface

	ip := net.ParseIP(cfg.Tun.IP)
	if ip == nil {
		fmt.Println("Invalid IP address")
		return
	}

	ifce, err = ifce.NewInterface(context.Background(), udpConns[0], tunDevice, routines, "", logger, api.Ip2VpnIp(ip))
	if err != nil {
		//return nil, fmt.Errorf("failed to initialize ifce: %s", err)
		panic(err)
	}

	for k, v := range cfg.StaticHostMap {
		ip := net.ParseIP(k)
		if ip == nil {
			fmt.Println("Invalid IP address")
			continue
		}
		udpAddr, err := net.ResolveUDPAddr("udp", v[0])
		if err != nil {
			fmt.Println("Error resolving UDP address:", err)
			continue
		}
		vip := api.Ip2VpnIp(ip)
		ifce.Hosts[vip] = &host.HostInfo{
			Remote: &udp.Addr{
				IP:   udpAddr.IP,
				Port: uint16(udpAddr.Port),
			},
			Remotes: host.RemoteList{},
			VpnIp:   vip,
		}
	}

	// TODO: Better way to attach these, probably want a new ifce in InterfaceConfig
	// I don't want to make this initial commit too far-reaching though
	ifce.Writers = udpConns

	ctrl := controllers.NewControllersManager(ifce, logger)

	ctrl.Start()
	ctrl.Shutdown()

	time.Sleep(10 * time.Second)
}
