package config

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"strconv"
	"time"
)

type Config struct {
	StaticHostMap map[string][]string `yaml:"static_host_map"`
	Lighthouse    LighthouseConfig    `yaml:"lighthouse"`
	Listen        ListenConfig        `yaml:"listen"`
	Tun           TunConfig           `yaml:"tun"`
	Handshake     HandshakeConfig     `yaml:"handshake"`
	Outbound      []OutboundRule      `yaml:"outbound"`
	Inbound       []InboundRule       `yaml:"inbound"`
}

type LighthouseConfig struct {
	Enabled        bool           `yaml:"enabled"`
	Interval       int            `yaml:"interval"`
	Hosts          []string       `yaml:"hosts"`
	LocalAllowList LocalAllowList `yaml:"local_allow_list"`
}

type LocalAllowList struct {
	Interfaces map[string]bool `yaml:"interfaces"`
}

type ListenConfig struct {
	Host        string `yaml:"host"`
	Port        int    `yaml:"port"`
	Batch       int    `yaml:"batch"`
	ReadBuffer  int    `yaml:"read_buffer"`
	WriteBuffer int    `yaml:"write_buffer"`
	Routines    int    `yaml:"routines"`
}

type TunConfig struct {
	Disabled bool `yaml:"disabled"`
	// Dev Name of the device. If not set, a default will be chosen by the OS.
	// For macOS: if set, must be in the form `utun[0-9]+`.
	// For NetBSD: Required to be set, must be in the form `tun[0-9]+`
	Dev                string `yaml:"dev"`
	IP                 string `yaml:"ip"`
	Mask               string `yaml:"mask"`
	DropLocalBroadcast bool   `yaml:"drop_local_broadcast"`
	DropMulticast      bool   `yaml:"drop_multicast"`
	TxQueue            int    `yaml:"tx_queue"`
	MTU                int    `yaml:"mtu"`
}

// HandshakeConfig 握手配置
type HandshakeConfig struct {
	HandshakeHost  time.Duration
	SyncLighthouse time.Duration
	TryInterval    time.Duration // 尝试间隔
	Retries        int           // 尝试次数
	TriggerBuffer  int           // 触发缓冲
	UseRelays      bool          // 是否使用中继
}

type OutboundRule struct {
	Port  AnyPort  `yaml:"port"`
	Proto string   `yaml:"proto"`
	Host  []string `yaml:"host"`
	// "allow" or "deny"
	Action string `yaml:"action"`
}

type InboundRule struct {
	Port  AnyPort  `yaml:"port"`
	Proto string   `yaml:"proto"`
	Host  []string `yaml:"host"`
	// "allow" or "deny"
	Action string `yaml:"action"`
}

type AnyPort uint16

const AnyPortValue AnyPort = 0

func (p AnyPort) ToUint16() uint16 {
	return uint16(p)
}

func (p *AnyPort) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var v interface{}
	if err := unmarshal(&v); err != nil {
		return err
	}
	switch value := v.(type) {
	case string:
		if value == "any" {
			*p = AnyPortValue
		} else {
			port, err := strconv.ParseUint(value, 10, 16)
			if err != nil {
				return err
			}
			*p = AnyPort(port)
		}
	case int, int32, int64:
		*p = AnyPort(value.(int))
	default:
		return fmt.Errorf("invalid port value: %v", v)
	}
	return nil
}

func Load(filename string) (*Config, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err = yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
