package configure

import (
	"gopkg.in/yaml.v3"
	"io"
	"os"
)

type Config struct {
	File      string
	Configure NovaConfig
}

func NewConfig(file string) *Config {
	return &Config{
		File: file,
	}
}

func (c *Config) LoadConfig() (err error) {
	return UnmarshalFrom(c.File, &c.Configure)
}

type NovaConfig struct {
	FQDN     string        `json:"FQDN" yaml:"FQDN"`
	IPv4Addr string        `json:"IPv4Addr" yaml:"IPv4Addr"`
	IPv6Addr string        `json:"IPv6Addr" yaml:"IPv6Addr"`
	Port     int           `json:"Port" yaml:"Port"`
	TLS      TLSSettings   `json:"TLSSettings" yaml:"TLSSettings"`
	Cache    CacheSettings `json:"CacheSettings" yaml:"CacheSettings"`
}

type TLSSettings struct {
	TLSType       string `json:"tlsType" yaml:"tlsType"`
	TLSMinVersion string `json:"tlsMinVersion" yaml:"tlsMinVersion"`
	KeyFile       string `json:"keyFile" yaml:"keyFile"`
	CertFile      string `json:"certFile" yaml:"certFile"`
	CAFile        string `json:"caFile" yaml:"caFile"`
}

type CacheSettings struct {
	CacheType string `json:"cacheType" yaml:"cacheType"`
}

func MarshalTo(file string, t interface{}) (err error) {
	return marshalTo(file, t)
}

func UnmarshalFrom(file string, t interface{}) (err error) {
	return unmarshalFrom(file, t)
}

func marshalTo(in string, t interface{}) (err error) {
	// try to open file...
	file, err := os.Open(in)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		err = file.Close()
	}(file)
	// marshal
	out, err := yaml.Marshal(t)
	if err != nil {
		return err
	}
	// write to the file...
	err = os.WriteFile(in, out, 0644)
	if err != nil {
		return err
	}
	return err
}

func unmarshalFrom(in string, t interface{}) (err error) {
	// try to open file...
	file, err := os.Open(in)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		err = file.Close()
	}(file)
	// read the file...
	data, err := io.ReadAll(file)
	if err != nil {
		return err
	}
	// unmarshal
	err = yaml.Unmarshal(data, t)
	if err != nil {
		return err
	}
	return err
}
