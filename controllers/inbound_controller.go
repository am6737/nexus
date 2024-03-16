package controllers

import (
	"errors"
	"fmt"
	"github.com/am6737/nexus/api"
	"github.com/am6737/nexus/transport/packet"
	"github.com/am6737/nexus/utils"
	"github.com/sirupsen/logrus"
	"io"
	"os"
	"runtime"
	"sync/atomic"
)

// InboundController 入站控制器 必须实现 interfaces.InboundController 接口
type InboundController struct {
	mtu        int
	closed     atomic.Bool
	localVpnIP api.VpnIp
	reader     io.ReadWriteCloser

	logger *logrus.Logger
}

func (ic *InboundController) Listen() {
	runtime.LockOSThread()

	p := &packet.Packet{}
	packet := make([]byte, ic.mtu)
	out := make([]byte, ic.mtu)
	nb := make([]byte, 12, 12)

	for {
		n, err := ic.reader.Read(packet)
		if err != nil {
			if errors.Is(err, os.ErrClosed) && ic.closed.Load() {
				return
			}
			ic.logger.WithError(err).Error("Error while reading outbound packet")
			// This only seems to happen when something fatal happens to the fd, so exit.
			os.Exit(2)
		}
		ic.consumeInsidePacket(packet[:n], p, nb, out)
	}
}

// Receive 接收从来源地址的数据
func (ic *InboundController) Receive(srcAddr string) ([]byte, error) {
	// 执行数据解密、解包等操作
	fmt.Println("Receiving data from", srcAddr)
	// 模拟接收数据
	return []byte("Received data"), nil
}

func (ic *InboundController) consumeInsidePacket(data []byte, packet *packet.Packet, nb []byte, out []byte) {
	if err := utils.ParsePacket(data, false, packet); err != nil {
		ic.logger.WithField("packet", packet).Debugf("Error while validating outbound packet: %s", err)
		return
	}

	fmt.Println("p RemoteIP => ", packet.RemoteIP)
	fmt.Println("itf.localVpnIP => ", ic.localVpnIP)

	if packet.RemoteIP == ic.localVpnIP {
		// Immediately forward packets from self to self.
		// This should only happen on Darwin-based and FreeBSD hosts, which
		// routes packets from the Nebula IP to the Nebula IP through the Nebula
		// TUN device.
		//if ifce.ImmediatelyForwardToSelf {
		fmt.Println("111")
		_, err := ic.reader.Write(data)
		if err != nil {
			ic.logger.WithError(err).Error("Failed to forward to tun")
		}
		//}
		// Otherwise, drop. On linux, we should never see these packets - Linux
		// routes packets from the nebula IP to the nebula IP through the loopback device.
		return
	}
}
