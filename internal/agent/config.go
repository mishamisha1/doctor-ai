package agent

import (
	"encoding/json"
	"os"
)

type Config struct {
	PolicyPath      string `json:"policyPath"`
	IntervalSeconds int    `json:"intervalSeconds"`
	Sysmon          struct {
		Enabled     bool   `json:"enabled"`
		AutoInstall bool   `json:"autoInstall"`
		ExePath     string `json:"exePath"`
		ConfigPath  string `json:"configPath"`
	} `json:"sysmon"`
	Output struct {
		Path string `json:"path"`
	} `json:"output"`
	State struct {
		Path string `json:"path"`
	} `json:"state"`

	EventLog struct {
		Enabled     bool `json:"enabled"`
		PollSeconds int  `json:"pollSeconds"`
		Sources     []struct {
			Log string `json:"log"`
			IDs []int  `json:"ids"`
		} `json:"sources"`
		MaxEventsPerPoll int `json:"maxEventsPerPoll"`
	} `json:"eventLog"`

	Registry struct {
		Enabled     bool `json:"enabled"`
		PollSeconds int  `json:"pollSeconds"`
		Watch       []struct {
			Hive string `json:"hive"`
			Path string `json:"path"`
		} `json:"watch"`
	} `json:"registry"`
}

func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	if c.IntervalSeconds <= 0 {
		c.IntervalSeconds = 10
	}
	return &c, nil
}
