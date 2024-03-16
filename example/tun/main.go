package main

import (
	"fmt"
	"github.com/am6737/nexus/tun"
	"net"
)

func main() {
	// 定义需要的参数
	defaultMTU := 1500
	cidr := &net.IPNet{
		IP:   net.IPv4(192, 168, 200, 9),
		Mask: net.IPv4Mask(255, 255, 255, 0),
	}

	// 创建新的 DarwinTun 实例
	tunDevice, err := tun.NewDarwinTun("", cidr, defaultMTU)
	if err != nil {
		fmt.Println("Error creating DarwinTun:", err)
		return
	}
	defer tunDevice.Close()

	// 获取设备信息
	deviceName := tunDevice.Name()
	fmt.Println("Device Name:", deviceName)

	mtu, err := tunDevice.MTU()
	if err != nil {
		fmt.Println("Error getting MTU:", err)
		return
	}
	fmt.Println("MTU:", mtu)

	cidrInfo := tunDevice.Cidr()
	fmt.Println("CIDR:", cidrInfo.String())

	// 模拟启动设备
	if err = tunDevice.Up(); err != nil {
		fmt.Println("Error bringing up the device:", err)
		return
	}
	fmt.Println("Device is up and running")

	go func() {
		for {
			// 读取数据
			data := make([]byte, 1500)
			n, err := tunDevice.Read(data)
			if err != nil {
				fmt.Println("Error reading from the device:", err)
				return
			}
			fmt.Println("data[:n] => ", data[:n])
			tunDevice.Write(data[:n])
			fmt.Println("Read", n, "bytes from the device")
		}
	}()

	for {

	}
}
