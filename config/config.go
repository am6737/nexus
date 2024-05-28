package config

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"io/ioutil"
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
	Persistence   Persistence         `yaml:"persistence"`
}

type LighthouseConfig struct {
	Enabled        bool           `yaml:"enabled"`
	Interval       int            `yaml:"interval"`
	Hosts          []string       `yaml:"hosts"`
	LocalAllowList LocalAllowList `yaml:"local_allow_list"`
}

type LocalAllowList struct {
	Interfaces map[string]bool `yaml:"ports"`
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
	Port  string   `yaml:"port"`
	Proto string   `yaml:"proto"`
	Host  []string `yaml:"host"`
	// "allow" or "deny"
	Action string `yaml:"action"`
}

type InboundRule struct {
	Port  string   `yaml:"port"`
	Proto string   `yaml:"proto"`
	Host  []string `yaml:"host"`
	// "allow" or "deny"
	Action string `yaml:"action"`
}

type Persistence struct {
	Enabled bool   `yaml:"enabled"`
	Url     string `yaml:"url"`
	Type    string `yaml:"type"`
	DB      string `yaml:"db"`
}

func (r OutboundRule) String() string {
	return fmt.Sprintf("port=%v proto=%s hosts=%v action=%s", r.Port, r.Proto, r.Host, r.Action)
}

func (r InboundRule) String() string {
	return fmt.Sprintf("port=%v proto=%s hosts=%v action=%s", r.Port, r.Proto, r.Host, r.Action)
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

var (
	defaultListen = ListenConfig{
		Host:        "0.0.0.0",
		Port:        7777,
		Batch:       64,
		ReadBuffer:  10485760,
		WriteBuffer: 10485760,
		Routines:    1,
	}

	defaultHandshake = HandshakeConfig{
		HandshakeHost:  30 * time.Second,
		SyncLighthouse: 60 * time.Second,
		TryInterval:    10 * time.Second, // 尝试间隔为10秒
		Retries:        3,                // 尝试次数为3次
		TriggerBuffer:  10,               // 触发缓冲为10
		UseRelays:      false,            // 不使用中继
	}

	defaultTun = TunConfig{
		Disabled:           false,
		Dev:                "nexus1",
		IP:                 "",
		Mask:               "",
		DropLocalBroadcast: false,
		DropMulticast:      false,
		TxQueue:            500,
		MTU:                1300,
	}

	defaultPersistence = Persistence{
		Enabled: false,
		Url:     "",
		Type:    "",
		DB:      "",
	}

	defaultLighthouse = LighthouseConfig{
		Enabled:        true,
		Interval:       60,
		Hosts:          nil,
		LocalAllowList: LocalAllowList{Interfaces: make(map[string]bool)},
	}

	defaultOutbound = []OutboundRule{
		{
			Port:   "any",
			Proto:  "icmp",
			Host:   nil,
			Action: "allow",
		},
	}

	defaultInbound = []InboundRule{
		{
			Port:   "any",
			Proto:  "icmp",
			Host:   nil,
			Action: "allow",
		},
	}
)

// GenerateConfigTemplate 生成通用配置模板
func GenerateConfigTemplate() Config {
	return Config{
		StaticHostMap: make(map[string][]string),
		Lighthouse:    defaultLighthouse,
		Listen:        defaultListen,
		Tun:           defaultTun,
		Handshake:     defaultHandshake,
		//Outbound:      defaultOutbound,
		//Inbound:       defaultInbound,
	}
}
