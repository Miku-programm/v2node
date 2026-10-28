package conf

import (
	"fmt"
	"os"

	"github.com/spf13/viper"
)

const DefaultNodeRetryCount = 1
const DefaultNodeTimeout = 15

type Conf struct {
	LogConfig      LogConfig      `mapstructure:"Log"`
	NodeConfigs    []NodeConfig   `mapstructure:"Nodes"`
	PprofPort      int            `mapstructure:"PprofPort"`
	ProbeLogConfig ProbeLogConfig `mapstructure:"ProbeLog"`
}

// ProbeLogConfig 控制探测/扫描行为记录（抓包 + xray 日志）以及上传 ClickHouse
type ProbeLogConfig struct {
	Enable           bool             `mapstructure:"Enable"`
	NodeName         string           `mapstructure:"NodeName"`
	Interface        string           `mapstructure:"Interface"`
	Capture          bool             `mapstructure:"Capture"`
	Direction        string           `mapstructure:"Direction"` // inbound / control / full
	ExtraPorts       []int            `mapstructure:"ExtraPorts"`
	GeoTags          []string         `mapstructure:"GeoTags"`
	MaxEventsPerSec  int              `mapstructure:"MaxEventsPerSec"`
	MaxPerSourceSec  int              `mapstructure:"MaxPerSourceSec"`
	PayloadHeadBytes int              `mapstructure:"PayloadHeadBytes"`
	AuthedSampleRate float64          `mapstructure:"AuthedSampleRate"`
	XrayLogLevel     string           `mapstructure:"XrayLogLevel"`
	LocalFile        string           `mapstructure:"LocalFile"`
	ClickHouse       ClickHouseConfig `mapstructure:"ClickHouse"`
}

type ClickHouseConfig struct {
	URL           string `mapstructure:"URL"`
	Database      string `mapstructure:"Database"`
	Table         string `mapstructure:"Table"`
	Username      string `mapstructure:"Username"`
	Password      string `mapstructure:"Password"`
	BatchSize     int    `mapstructure:"BatchSize"`
	FlushInterval int    `mapstructure:"FlushInterval"`
	BufferSize    int    `mapstructure:"BufferSize"`
	Timeout       int    `mapstructure:"Timeout"`
}

type LogConfig struct {
	Level  string `mapstructure:"Level"`
	Output string `mapstructure:"Output"`
	Access string `mapstructure:"Access"`
}

type NodeConfig struct {
	APIHost    string `mapstructure:"ApiHost"`
	NodeID     int    `mapstructure:"NodeID"`
	Key        string `mapstructure:"ApiKey"`
	Timeout    int    `mapstructure:"Timeout"`
	RetryCount *int   `mapstructure:"RetryCount"`
}

func New() *Conf {
	return &Conf{
		LogConfig: LogConfig{
			Level:  "info",
			Output: "",
			Access: "none",
		},
		ProbeLogConfig: ProbeLogConfig{
			Capture:          true,
			Direction:        "control",
			GeoTags:          []string{"cn"},
			MaxEventsPerSec:  2000,
			MaxPerSourceSec:  200,
			PayloadHeadBytes: 64,
			AuthedSampleRate: 1,
			XrayLogLevel:     "info",
			ClickHouse: ClickHouseConfig{
				Database:      "v2node",
				Table:         "probe_events",
				BatchSize:     2000,
				FlushInterval: 5,
				BufferSize:    200000,
				Timeout:       15,
			},
		},
	}
}

func (p *Conf) LoadFromPath(filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open config file error: %s", err)
	}
	defer f.Close()
	v := viper.New()
	v.SetConfigFile(filePath)
	if err := v.ReadInConfig(); err != nil {
		return fmt.Errorf("read config file error: %s", err)
	}
	if err := v.Unmarshal(p); err != nil {
		return fmt.Errorf("unmarshal config error: %s", err)
	}
	for i := range p.NodeConfigs {
		if p.NodeConfigs[i].RetryCount == nil {
			p.NodeConfigs[i].RetryCount = intPtr(DefaultNodeRetryCount)
		}
	}
	return nil
}

func intPtr(v int) *int {
	return &v
}
