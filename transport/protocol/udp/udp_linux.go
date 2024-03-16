package udp

import (
	"encoding/binary"
	"fmt"
	"github.com/am6737/nexus/config"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"net"
	"syscall"
	"unsafe"
)

func maybeIPV4(ip net.IP) (net.IP, bool) {
	ip4 := ip.To4()
	if ip4 != nil {
		return ip4, true
	}
	return ip, false
}

type StdConn struct {
	sysFd int
	isV4  bool
	l     *logrus.Logger
	batch int
}

func NewListener(l *logrus.Logger, ip net.IP, port int, multi bool, batch int) (Conn, error) {
	ipV4, isV4 := maybeIPV4(ip)
	af := unix.AF_INET6
	if isV4 {
		af = unix.AF_INET
	}
	syscall.ForkLock.RLock()
	fd, err := unix.Socket(af, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	if err == nil {
		unix.CloseOnExec(fd)
	}
	syscall.ForkLock.RUnlock()

	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("unable to open socket: %s", err)
	}

	if multi {
		if err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
			return nil, fmt.Errorf("unable to set SO_REUSEPORT: %s", err)
		}
	}

	//TODO: support multiple listening IPs (for limiting ipv6)
	var sa unix.Sockaddr
	if isV4 {
		sa4 := &unix.SockaddrInet4{Port: port}
		copy(sa4.Addr[:], ipV4)
		sa = sa4
	} else {
		sa6 := &unix.SockaddrInet6{Port: port}
		copy(sa6.Addr[:], ip.To16())
		sa = sa6
	}
	if err = unix.Bind(fd, sa); err != nil {
		return nil, fmt.Errorf("unable to bind to socket: %s", err)
	}

	//TODO: this may be useful for forcing threads into specific cores
	//unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_INCOMING_CPU, x)
	//v, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_INCOMING_CPU)
	//l.Println(v, err)

	return &StdConn{sysFd: fd, isV4: isV4, l: l, batch: batch}, err
}

func (s *StdConn) Rebind() error {
	return nil
}

func (s *StdConn) SetRecvBuffer(n int) error {
	return unix.SetsockoptInt(s.sysFd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, n)
}

func (s *StdConn) SetSendBuffer(n int) error {
	return unix.SetsockoptInt(s.sysFd, unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, n)
}

func (s *StdConn) GetRecvBuffer() (int, error) {
	return unix.GetsockoptInt(int(s.sysFd), unix.SOL_SOCKET, unix.SO_RCVBUF)
}

func (s *StdConn) GetSendBuffer() (int, error) {
	return unix.GetsockoptInt(int(s.sysFd), unix.SOL_SOCKET, unix.SO_SNDBUF)
}

func (s *StdConn) LocalAddr() (*Addr, error) {
	sa, err := unix.Getsockname(s.sysFd)
	if err != nil {
		return nil, err
	}

	addr := &Addr{}
	switch sa := sa.(type) {
	case *unix.SockaddrInet4:
		addr.IP = net.IP{sa.Addr[0], sa.Addr[1], sa.Addr[2], sa.Addr[3]}.To16()
		addr.Port = uint16(sa.Port)
	case *unix.SockaddrInet6:
		addr.IP = sa.Addr[0:]
		addr.Port = uint16(sa.Port)
	}

	return addr, nil
}

func (s *StdConn) ListenOut(r EncReader) {
	plaintext := make([]byte, MTU)
	//h := &header.Header{}
	//fwPacket := &packet.Packet{}
	udpAddr := &Addr{}

	//TODO: should we track this?
	//metric := metrics.GetOrRegisterHistogram("test.batch_read", nil, metrics.NewExpDecaySample(1028, 0.015))
	msgs, buffers, names := s.PrepareRawMessages(s.batch)
	read := s.ReadMulti
	if s.batch == 1 {
		read = s.ReadSingle
	}

	for {
		n, err := read(msgs)
		if err != nil {
			s.l.WithError(err).Debug("udp socket is closed, exiting read loop")
			return
		}

		//metric.Update(int64(n))
		for i := 0; i < n; i++ {
			if s.isV4 {
				udpAddr.IP = names[i][4:8]
			} else {
				udpAddr.IP = names[i][8:24]
			}
			udpAddr.Port = binary.BigEndian.Uint16(names[i][2:4])
			r(udpAddr, plaintext[:0], buffers[i][:msgs[i].Len])
		}
	}
}

func (s *StdConn) ReadSingle(msgs []rawMessage) (int, error) {
	for {
		n, _, err := unix.Syscall6(
			unix.SYS_RECVMSG,
			uintptr(s.sysFd),
			uintptr(unsafe.Pointer(&(msgs[0].Hdr))),
			0,
			0,
			0,
			0,
		)

		if err != 0 {
			return 0, &net.OpError{Op: "recvmsg", Err: err}
		}

		msgs[0].Len = uint32(n)
		return 1, nil
	}
}

func (s *StdConn) ReadMulti(msgs []rawMessage) (int, error) {
	for {
		n, _, err := unix.Syscall6(
			unix.SYS_RECVMMSG,
			uintptr(s.sysFd),
			uintptr(unsafe.Pointer(&msgs[0])),
			uintptr(len(msgs)),
			unix.MSG_WAITFORONE,
			0,
			0,
		)

		if err != 0 {
			return 0, &net.OpError{Op: "recvmmsg", Err: err}
		}

		return int(n), nil
	}
}

type iovec struct {
	Base *byte
	Len  uint64
}

type msghdr struct {
	Name       *byte
	Namelen    uint32
	Pad0       [4]byte
	Iov        *iovec
	Iovlen     uint64
	Control    *byte
	Controllen uint64
	Flags      int32
	Pad1       [4]byte
}

type rawMessage struct {
	Hdr  msghdr
	Len  uint32
	Pad0 [4]byte
}

func (s *StdConn) PrepareRawMessages(n int) ([]rawMessage, [][]byte, [][]byte) {
	msgs := make([]rawMessage, n)
	buffers := make([][]byte, n)
	names := make([][]byte, n)

	for i := range msgs {
		buffers[i] = make([]byte, MTU)
		names[i] = make([]byte, unix.SizeofSockaddrInet6)

		//TODO: this is still silly, no need for an array
		vs := []iovec{
			{Base: &buffers[i][0], Len: uint64(len(buffers[i]))},
		}

		msgs[i].Hdr.Iov = &vs[0]
		msgs[i].Hdr.Iovlen = uint64(len(vs))

		msgs[i].Hdr.Name = &names[i][0]
		msgs[i].Hdr.Namelen = uint32(len(names[i]))
	}

	return msgs, buffers, names
}

func (s *StdConn) WriteTo(b []byte, addr *Addr) error {
	//TODO implement me
	panic("implement me")
}

func (s *StdConn) ReloadConfig(c *config.Config) {
	//TODO implement me
	panic("implement me")
}

func (s *StdConn) Close() error {
	//TODO implement me
	panic("implement me")
}
