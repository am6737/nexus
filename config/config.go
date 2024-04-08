package config

import (
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
	TryInterval   time.Duration // 尝试间隔
	Retries       int           // 尝试次数
	TriggerBuffer int           // 触发缓冲
	UseRelays     bool          // 是否使用中继
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
