//go:build (!linux || android) && !e2e_testing
// +build !linux android
// +build !e2e_testing

package udp

import (
	"fmt"
	"github.com/am6737/nexus/config"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"net"
)

type GenericConn struct {
	*net.UDPConn
	l *logrus.Logger
}

func (u *GenericConn) LocalAddr() (*Addr, error) {
	a := u.UDPConn.LocalAddr()

	switch v := a.(type) {
	case *net.UDPAddr:
		addr := &Addr{IP: make([]byte, len(v.IP))}
		copy(addr.IP, v.IP)
		addr.Port = uint16(v.Port)
		return addr, nil

	default:
		return nil, fmt.Errorf("LocalAddr returned: %#v", a)
	}
}

func (u *GenericConn) ListenOut(r EncReader) {
	plaintext := make([]byte, MTU)
	buffer := make([]byte, MTU)
	udpAddr := &Addr{IP: make([]byte, 16)}

	for {
		// Just read one packet at a time
		n, rua, err := u.ReadFromUDP(buffer)
		if err != nil {
			u.l.WithError(err).Debug("udp socket is closed, exiting read loop")
			return
		}

		udpAddr.IP = rua.IP
		udpAddr.Port = uint16(rua.Port)
		r(udpAddr, plaintext[:0], buffer[:n])
	}
}

func (u *GenericConn) WriteTo(b []byte, addr *Addr) error {
	_, err := u.UDPConn.WriteToUDP(b, &net.UDPAddr{IP: addr.IP, Port: int(addr.Port)})
	return err
}

func (u *GenericConn) ReloadConfig(c *config.Config) {

}

func NewGenericListener(l *logrus.Logger, ip net.IP, port int, multi bool, batch int) (Conn, error) {
	lc := NewListenConfig(multi)
	pc, err := lc.ListenPacket(context.TODO(), "udp", net.JoinHostPort(ip.String(), fmt.Sprintf("%v", port)))
	if err != nil {
		return nil, err
	}
	if uc, ok := pc.(*net.UDPConn); ok {
		return &GenericConn{UDPConn: uc, l: l}, nil
	}
	return nil, fmt.Errorf("unexpected PacketConn: %T %#v", pc, pc)
}
