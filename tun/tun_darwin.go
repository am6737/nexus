//go:build !ios && !e2e_testing
// +build !ios,!e2e_testing

package tun

import (
	"errors"
	"fmt"
	"io"
	"log"

	"net"
	"os"
	"syscall"
	"unsafe"

	netroute "golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

const (
	appleUTUNCtl = "com.apple.net.utun_control"
	//appleCTLIOCGINFO = (0x40000000 | 0x80000000) | ((100 & 0x1fff) << 16) | uint32(byte('N'))<<8 | 3

	appleCTLIOCGINFO = 3227799043

	defaultMTU = 1500
)

type sockaddrCtl struct {
	scLen      uint8
	scFamily   uint8
	ssSysaddr  uint16
	scID       uint32
	scUnit     uint32
	scReserved [5]uint32
}

var sockaddrCtlSize uintptr = 32

// tun 实现了 Device 接口
type tun struct {
	fd int
	//file       *os.File
	io.ReadWriteCloser
	device     string
	addr       [4]byte
	mask       [4]byte
	defaultMTU int
	ifra       ifreqAddr
	cidr       *net.IPNet

	// cache out buffer since we need to prepend 4 bytes for tun metadata
	out []byte
}

type ifreqAddr struct {
	Name [16]byte
	Addr unix.RawSockaddrInet4
	pad  [8]byte
}

type ifReq struct {
	Name  [16]byte
	Flags uint16
	pad   [8]byte
}

type ifreqMTU struct {
	Name [16]byte
	MTU  int32
	pad  [8]byte
}

// newTun creates a new tun instance.
// It initializes and configures a new tun device with the provided parameters.
// name is the name of the device.
// cidr is the network CIDR of the device.
// defaultMTU is the default Maximum Transmission Unit (MTU) of the device.
// It returns a Device ifce and an error if any.
func newTun(name string, cidr *net.IPNet, mtu int, txQueueLen int, multiqueue bool) (Device, error) {
	fmt.Println("cidr => ", cidr)
	var fd int
	var err error
	ifIndex := -1
	if name != "" && name != "utun" {
		_, err := fmt.Sscanf(name, "utun%d", &ifIndex)
		if err != nil || ifIndex < 0 {
			// NOTE: we don't make this error so we don't break existing
			// configs that set a name before it was used.
			//logger.Warn("ifce name must be utun[0-9]+ on Darwin, ignoring")
			log.Println("ifce name must be utun[0-9]+ on Darwin, ignoring")
			ifIndex = -1
		}
	}

	if mtu == 0 {
		mtu = defaultMTU
	}

	// Create a new system socket for tun
	if fd, err = syscall.Socket(syscall.AF_SYSTEM, syscall.SOCK_DGRAM, 2); err != nil {
		return nil, fmt.Errorf("system socket: %v", err)
	}

	// Get control information for utun device
	var ctlInfo = &struct {
		ctlID   uint32
		ctlName [96]byte
	}{}
	copy(ctlInfo.ctlName[:], appleUTUNCtl)
	if err = ioctl(uintptr(fd), uintptr(appleCTLIOCGINFO), uintptr(unsafe.Pointer(ctlInfo))); err != nil {
		return nil, fmt.Errorf("CTLIOCGINFO: %v", err)
	}

	// Connect to the utun control socket
	sc := sockaddrCtl{
		scLen:     uint8(sockaddrCtlSize),
		scFamily:  unix.AF_SYSTEM,
		ssSysaddr: unix.AF_SYS_CONTROL,
		scID:      ctlInfo.ctlID,
		scUnit:    uint32(ifIndex) + 1,
	}
	_, _, errno := unix.RawSyscall(
		unix.SYS_CONNECT,
		uintptr(fd),
		uintptr(unsafe.Pointer(&sc)),
		sockaddrCtlSize,
	)
	if errno != 0 {
		return nil, fmt.Errorf("SYS_CONNECT: %v", errno)
	}

	// Get the ifce name for the utun device
	var ifName struct {
		name [16]byte
	}
	ifNameSize := uintptr(len(ifName.name))
	_, _, errno = syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd),
		2, // SYSPROTO_CONTROL
		2, // UTUN_OPT_IFNAME
		uintptr(unsafe.Pointer(&ifName)),
		uintptr(unsafe.Pointer(&ifNameSize)), 0)
	if errno != 0 {
		return nil, fmt.Errorf("SYS_GETSOCKOPT: %v", errno)
	}

	// Set the socket to non-blocking mode
	if err = syscall.SetNonblock(fd, true); err != nil {
		return nil, fmt.Errorf("SetNonblock: %v", err)
	}

	// Create a new file from the file descriptor
	file := os.NewFile(uintptr(fd), "")
	devName := string(ifName.name[:ifNameSize-1])

	return &tun{
		fd: fd,
		//file:       file,
		ReadWriteCloser: file,
		device:          devName,
		defaultMTU:      mtu,
		cidr:            cidr,
	}, nil
}

func (t *tun) MTU() int {
	return t.defaultMTU
}

func (t *tun) Cidr() *net.IPNet {
	return t.cidr
}

func (t *tun) Name() string {
	return t.device
}

// Up activates the tun instance, configures the network ifce, and brings it up.
// It sets the IP address, subnet mask, and MTU of the device, and flags the ifce as up and running.
// If present, it also adds to the routing table.
// If successful, it returns nil; otherwise, it returns an error.
func (t *tun) Up() error {
	devName := t.deviceBytes()

	var addr, mask [4]byte

	// Copy the IP address and subnet mask to their respective arrays
	copy(addr[:], t.cidr.IP.To4())
	copy(mask[:], t.cidr.Mask)

	// Create a socket to configure the network ifce
	s, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM,
		unix.IPPROTO_IP,
	)
	if err != nil {
		return err
	}
	defer unix.Close(s)

	fd := uintptr(s)

	// Construct the device's IP address structure
	ifra := ifreqAddr{
		Name: devName,
		Addr: unix.RawSockaddrInet4{
			Family: unix.AF_INET,
			Addr:   addr,
		},
	}

	// Set the device's IP address
	if err := ioctl(fd, unix.SIOCSIFADDR, uintptr(unsafe.Pointer(&ifra))); err != nil {
		log.Printf("unable to set device IP address: %v", err)
		return err
	}

	// Set the device's subnet mask
	ifra.Addr.Addr = mask
	if err := ioctl(fd, unix.SIOCSIFNETMASK, uintptr(unsafe.Pointer(&ifra))); err != nil {
		log.Printf("unable to set device network: %v", err)
		return err
	}

	// Get the current flags of the device
	ifrf := ifReq{Name: devName}
	if err := ioctl(fd, unix.SIOCGIFFLAGS, uintptr(unsafe.Pointer(&ifrf))); err != nil {
		log.Printf("unable to get device flags: %v", err)
		return err
	}

	// Set the MTU of the device
	ifm := ifreqMTU{Name: devName, MTU: int32(t.defaultMTU)}
	if err := ioctl(fd, unix.SIOCSIFMTU, uintptr(unsafe.Pointer(&ifm))); err != nil {
		log.Printf("unable to set device MTU: %v", err)
		return err
	}

	// Bring the ifce up
	ifrf.Flags = ifrf.Flags | unix.IFF_UP
	if err := ioctl(fd, unix.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifrf))); err != nil {
		log.Printf("unable to set device flags: %v", err)
		return err
	}

	// Create a route socket for adding routes
	routeSock, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		log.Printf("unable to create route socket: %v", err)
		return err
	}
	defer func() {
		unix.Shutdown(routeSock, unix.SHUT_RDWR)
		if err := unix.Close(routeSock); err != nil {
			log.Printf("unable to close route socket: %v", err)
		}
	}()

	// Get the link address of the device
	routeAddr := &netroute.Inet4Addr{}
	maskAddr := &netroute.Inet4Addr{}
	linkAddr, err := getLinkAddr(t.device)
	if err != nil {
		log.Printf("unable to get link address: %v", err)
		return err
	}
	if linkAddr == nil {
		return errors.New("unable to get link address")
	}

	// Copy the addresses to the route address structures
	copy(routeAddr.IP[:], addr[:])
	copy(maskAddr.IP[:], mask[:])

	fmt.Println("routeAddr => ", routeAddr)
	fmt.Println("maskAddr => ", maskAddr)
	fmt.Println("linkAddr => ", linkAddr)

	// Add the route to the routing table
	if err = addRoute(routeSock, routeAddr, maskAddr, linkAddr); err != nil {
		if errors.Is(err, unix.EEXIST) {
			err = fmt.Errorf("unable to add tun route, identical route already exists")
		}
		//return err
	}

	// Flag the ifce as up and running
	ifrf.Flags = ifrf.Flags | unix.IFF_UP | unix.IFF_RUNNING
	if err := ioctl(uintptr(fd), unix.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifrf))); err != nil {
		log.Printf("unable to set device flags: %v", err)
		return err
	}

	return nil
}

func (t *tun) Down() error {
	// TODO: Implement shutting down the ifce
	return nil
}

func (t *tun) Read(to []byte) (int, error) {

	buf := make([]byte, len(to)+4)

	n, err := t.ReadWriteCloser.Read(buf)

	copy(to, buf[4:])
	return n - 4, err
}

// Write is only valid for single threaded use
func (t *tun) Write(from []byte) (int, error) {
	buf := t.out
	if cap(buf) < len(from)+4 {
		buf = make([]byte, len(from)+4)
		t.out = buf
	}
	buf = buf[:len(from)+4]

	if len(from) == 0 {
		return 0, syscall.EIO
	}

	// Determine the IP Family for the NULL L2 Header
	ipVer := from[0] >> 4
	if ipVer == 4 {
		buf[3] = syscall.AF_INET
	} else if ipVer == 6 {
		buf[3] = syscall.AF_INET6
	} else {
		return 0, fmt.Errorf("unable to determine IP version from packet")
	}

	copy(buf[4:], from)

	n, err := t.ReadWriteCloser.Write(buf)
	return n - 4, err
}

func (t *tun) Close() error {
	return t.ReadWriteCloser.Close()
}

func (t *tun) deviceBytes() (o [16]byte) {
	for i, c := range t.device {
		o[i] = byte(c)
	}
	return
}

// Get the LinkAddr for the ifce of the given name
// TODO: Is there an easier way to fetch this when we create the ifce?
// Maybe SIOCGIFINDEX? but this doesn't appear to exist in the darwin headers.
func getLinkAddr(name string) (*netroute.LinkAddr, error) {
	rib, err := netroute.FetchRIB(unix.AF_UNSPEC, unix.NET_RT_IFLIST, 0)
	if err != nil {
		return nil, err
	}
	msgs, err := netroute.ParseRIB(unix.NET_RT_IFLIST, rib)
	if err != nil {
		return nil, err
	}

	for _, m := range msgs {
		switch m := m.(type) {
		case *netroute.InterfaceMessage:
			if m.Name == name {
				sa, ok := m.Addrs[unix.RTAX_IFP].(*netroute.LinkAddr)
				if ok {
					return sa, nil
				}
			}
		}
	}

	return nil, nil
}

func addRoute(sock int, addr, mask *netroute.Inet4Addr, link *netroute.LinkAddr) error {
	r := netroute.RouteMessage{
		Version: unix.RTM_VERSION,
		Type:    unix.RTM_ADD,
		Flags:   unix.RTF_UP,
		Seq:     1,
		Addrs: []netroute.Addr{
			unix.RTAX_DST:     addr,
			unix.RTAX_GATEWAY: link,
			unix.RTAX_NETMASK: mask,
		},
	}

	data, err := r.Marshal()
	if err != nil {
		return fmt.Errorf("failed to create route.RouteMessage: %w", err)
	}
	_, err = unix.Write(sock, data[:])
	if err != nil {
		return fmt.Errorf("failed to write route.RouteMessage to socket: %w", err)
	}

	return nil
}

func ioctl(a1, a2, a3 uintptr) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, a1, a2, a3)
	if errno != 0 {
		return errno
	}
	return nil
}
