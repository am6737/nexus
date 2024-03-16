package host

import (
	"github.com/am6737/nexus/api"
	"github.com/am6737/nexus/transport/protocol/udp"
	"github.com/flynn/noise"
	"sync"
	"sync/atomic"
)

type HostInfo struct {
	Remote  *udp.Addr
	Remotes RemoteList
	//ConnectionState *ConnectionState
	RemoteIndexId uint32
	LocalIndexId  uint32
	VpnIp         api.VpnIp
}

// RemoteList is a unifying concept for lighthouse servers and clients as well as hostinfos.
// It serves as a local cache of query replies, host update notifications, and locally learned addresses
type RemoteList struct {
	// Every interaction with internals requires a lock!
	sync.RWMutex

	// A deduplicated set of addresses. Any accessor should lock beforehand.
	addrs []*udp.Addr
}

type ConnectionState struct {
	//eKey           *CipherState
	//dKey           *CipherState
	H              *noise.HandshakeState
	initiator      bool
	messageCounter atomic.Uint64
	//window         *Bits
	writeLock sync.Mutex
}
