package api

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/am6737/nexus/config"
	"net"
	"net/netip"
)

const (
	NetWorkNamePrefix = "network_"
)

type CreateNetwork struct {
	Name string `json:"name"`
	Cidr string `json:"cidr"`
}

type CreateNetworkResponse struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Cidr      string `json:"cidr"`
	CreatedAt string `json:"created_at"`
}

type Network struct {
	ID           string  `json:"id"`
	Name         string  `json:"name"`
	Cidr         string  `json:"cidr"`
	UsedIPs      []VpnIP `json:"used_ips"`      // 存储分配的地址
	AvailableIPs []VpnIP `json:"available_ips"` // 存储可用的地址
	CreatedAt    int64   `json:"created_at"`
}

// Host 表示一个主机
type Host struct {
	ID         string
	Name       string
	NetworkID  string
	Role       string
	CreatedAt  int64
	LastSeenAt int64
	// StaticAddresses A list of static addresses for the host
	StaticAddresses []string

	IPAddress    VpnIP
	Port         int
	IsLighthouse bool

	Tags map[string]interface{}

	// Config 主机的配置文件
	Config config.Config
}

type QueryNetwork struct {
	Name          string
	Cidr          string
	SortDirection string // 排序方向
	IncludeCounts bool
	PageSize      int // 每页大小
	PageNumber    int // 页码
}

type UpdateNetwork struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// FindOptions 定义了查询主机数据时的过滤和排序选项
type FindOptions struct {
	// 可以添加各种过滤条件,如按名称、IP、标签等进行过滤
	Filters map[string]interface{}

	// 可以添加排序选项,如按创建时间、名称等进行排序
	Sort map[string]interface{} // 1 for ascending, -1 for descending

	// 分页选项
	Limit  int
	Offset int

	NetworkID    string
	IPAddress    string
	Role         string
	Name         string
	IsLighthouse bool
}

type VpnIP uint32

const maxIPv4StringLen = len("255.255.255.255")

func (ip VpnIP) String() string {
	b := make([]byte, maxIPv4StringLen)

	n := ubtoa(b, 0, byte(ip>>24))
	b[n] = '.'
	n++

	n += ubtoa(b, n, byte(ip>>16&255))
	b[n] = '.'
	n++

	n += ubtoa(b, n, byte(ip>>8&255))
	b[n] = '.'
	n++

	n += ubtoa(b, n, byte(ip&255))
	return string(b[:n])
}

func (ip VpnIP) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("\"%s\"", ip.String())), nil
}

func (ip VpnIP) ToIP() net.IP {
	nip := make(net.IP, 4)
	binary.BigEndian.PutUint32(nip, uint32(ip))
	return nip
}

func (ip VpnIP) ToNetIpAddr() netip.Addr {
	var nip [4]byte
	binary.BigEndian.PutUint32(nip[:], uint32(ip))
	return netip.AddrFrom4(nip)
}

func (ip VpnIP) ToNetIP() net.IP {
	ipStr := fmt.Sprintf("%d.%d.%d.%d", byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
	return net.ParseIP(ipStr)
}

func Ip2VpnIp(ip []byte) VpnIP {
	if len(ip) == 16 {
		return VpnIP(binary.BigEndian.Uint32(ip[12:16]))
	}
	return VpnIP(binary.BigEndian.Uint32(ip))
}

func ToNetIpAddr(ip net.IP) (netip.Addr, error) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, fmt.Errorf("invalid net.IP: %v", ip)
	}
	return addr, nil
}

func ParseVpnIp(str string) (VpnIP, error) {
	ip := net.ParseIP(str)
	if ip == nil {
		return 0, fmt.Errorf("invalid IP address: %s", str)
	}
	ipBytes := ip.To4()
	if ipBytes == nil {
		return 0, fmt.Errorf("invalid IPv4 address: %s", str)
	}
	return VpnIP(binary.BigEndian.Uint32(ipBytes)), nil
}

func ToNetIpPrefix(ipNet net.IPNet) (netip.Prefix, error) {
	addr, err := ToNetIpAddr(ipNet.IP)
	if err != nil {
		return netip.Prefix{}, err
	}
	ones, bits := ipNet.Mask.Size()
	if ones == 0 && bits == 0 {
		return netip.Prefix{}, fmt.Errorf("invalid net.IP: %v", ipNet)
	}
	return netip.PrefixFrom(addr, ones), nil
}

// ubtoa encodes the string form of the integer v to dst[start:] and
// returns the number of bytes written to dst. The caller must ensure
// that dst has sufficient length.
func ubtoa(dst []byte, start int, v byte) int {
	if v < 10 {
		dst[start] = v + '0'
		return 1
	} else if v < 100 {
		dst[start+1] = v%10 + '0'
		dst[start] = v/10 + '0'
		return 2
	}

	dst[start+2] = v%10 + '0'
	dst[start+1] = (v/10)%10 + '0'
	dst[start] = v/100 + '0'
	return 3
}

func (ip *VpnIP) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	parsedIp, err := ParseVpnIp(s)
	if err != nil {
		return err
	}

	*ip = parsedIp
	return nil
}
