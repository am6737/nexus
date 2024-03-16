package tun

import (
	"io"
	"net"
)

type Device interface {
	io.ReadWriteCloser

	// MTU returns the MTU of the Device.
	MTU() (int, error)

	Cidr() *net.IPNet

	// Name returns the current device of the Device.
	Name() string

	// Events returns a channel of type Event, which is fed Device events.
	//Events() <-chan Event

	Up() error

	Down() error
}
