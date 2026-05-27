// Package config provides configuration management for ePDG.
// Based on 3GPP TS 23.402, TS 24.302, TS 33.402.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Config is the top-level ePDG configuration.
type Config struct {
	ePDG     ePDGConfig     `json:"epdg"`
	IKE      IKEConfig      `json:"ike"`
	EAP      EAPConfig      `json:"eap"`
	GTP      GTPConfig      `json:"gtp"`
	Diameter DiameterConfig `json:"diameter"`
	Database DatabaseConfig `json:"database"`
	Logger   LoggerConfig   `json:"logger"`
}

// ePDGConfig holds general ePDG node configuration.
type ePDGConfig struct {
	// FQDN is the ePDG fully qualified domain name (used in IKEv2 ID payload).
	FQDN string `json:"fqdn"`
	// PublicIP is the ePDG public IP address (SWu interface).
	PublicIP string `json:"public_ip"`
	// InternalIP is the ePDG internal IP address (S2b/SWm interface).
	InternalIP string `json:"internal_ip"`
	// PLMN is the serving PLMN (MCC+MNC, e.g. "46000").
	PLMN string `json:"plmn"`
	// CertFile is the path to the ePDG TLS/IKE certificate (PEM).
	CertFile string `json:"cert_file"`
	// KeyFile is the path to the ePDG private key (PEM).
	KeyFile string `json:"key_file"`
	// CAFile is the path to the trusted CA certificate (PEM).
	CAFile string `json:"ca_file"`
}

// IKEConfig holds IKEv2 configuration (3GPP TS 24.302 §7).
type IKEConfig struct {
	// ListenAddr is the UDP address to listen on (default ":500").
	ListenAddr string `json:"listen_addr"`
	// NATTListenAddr is the NAT-T UDP address (default ":4500").
	NATTListenAddr string `json:"natt_listen_addr"`
	// Proposals lists the supported IKE SA proposals (cipher suites).
	Proposals []IKEProposal `json:"proposals"`
	// ChildProposals lists the supported Child SA (IPSec) proposals.
	ChildProposals []IKEProposal `json:"child_proposals"`
	// SALifetime is the IKE SA lifetime.
	SALifetime time.Duration `json:"sa_lifetime"`
	// ChildSALifetime is the Child SA lifetime.
	ChildSALifetime time.Duration `json:"child_sa_lifetime"`
	// DPDInterval is the Dead Peer Detection interval.
	DPDInterval time.Duration `json:"dpd_interval"`
	// DPDTimeout is the Dead Peer Detection timeout.
	DPDTimeout time.Duration `json:"dpd_timeout"`
	// ReauthTime is the IKEv2 re-authentication interval.
	ReauthTime time.Duration `json:"reauth_time"`
}

// IKEProposal represents an IKEv2 SA proposal (RFC 7296 §3.3).
type IKEProposal struct {
	// EncAlg is the encryption algorithm (e.g. "AES_CBC_128", "AES_GCM_16_128").
	EncAlg string `json:"enc_alg"`
	// IntegAlg is the integrity algorithm (e.g. "HMAC_SHA2_256_128").
	IntegAlg string `json:"integ_alg"`
	// PRFAlg is the pseudo-random function (e.g. "PRF_HMAC_SHA2_256").
	PRFAlg string `json:"prf_alg"`
	// DHGroup is the Diffie-Hellman group (e.g. "MODP_2048", "ECP_256").
	DHGroup string `json:"dh_group"`
	// ESNEnabled enables Extended Sequence Numbers for Child SA.
	ESNEnabled bool `json:"esn_enabled"`
}

// EAPConfig holds EAP-AKA/AKA' configuration (3GPP TS 33.402).
type EAPConfig struct {
	// Method selects EAP method: "EAP-AKA" or "EAP-AKA-PRIME".
	Method string `json:"method"`
	// MaxRetries is the maximum number of EAP retransmissions.
	MaxRetries int `json:"max_retries"`
	// Timeout is the EAP exchange timeout.
	Timeout time.Duration `json:"timeout"`
}

// GTPConfig holds GTP-U configuration (3GPP TS 29.281).
type GTPConfig struct {
	// ListenAddr is the GTP-U UDP listen address (default ":2152").
	ListenAddr string `json:"listen_addr"`
	// PGWAddr is the P-GW GTP-U address for S2b interface.
	PGWAddr string `json:"pgw_addr"`
	// BufferSize is the GTP-U packet buffer size in bytes.
	BufferSize int `json:"buffer_size"`
}

// DiameterConfig holds Diameter/SWm interface configuration (3GPP TS 29.273).
type DiameterConfig struct {
	// Addr is the local Diameter address.
	Addr string `json:"addr"`
	// AAAServerAddr is the 3GPP AAA Server address.
	AAAServerAddr string `json:"aaa_server_addr"`
	// OriginHost is the Diameter Origin-Host AVP value.
	OriginHost string `json:"origin_host"`
	// OriginRealm is the Diameter Origin-Realm AVP value.
	OriginRealm string `json:"origin_realm"`
	// DestinationRealm is the Diameter Destination-Realm AVP value.
	DestinationRealm string `json:"destination_realm"`
	// TLSEnabled enables TLS for Diameter connections.
	TLSEnabled bool `json:"tls_enabled"`
	// CertFile is the Diameter TLS certificate.
	CertFile string `json:"cert_file"`
	// KeyFile is the Diameter TLS key.
	KeyFile string `json:"key_file"`
	// Timeout is the Diameter request timeout.
	Timeout time.Duration `json:"timeout"`
	// RetryCount is the number of Diameter request retries.
	RetryCount int `json:"retry_count"`
}

// DatabaseConfig selects and configures the session store.
type DatabaseConfig struct {
	// Type is "sqlite" or "mysql".
	Type string `json:"type"`
	// SQLitePath is the SQLite database file path.
	SQLitePath string `json:"sqlite_path"`
	// MySQL holds MySQL connection parameters.
	MySQL MySQLConfig `json:"mysql"`
}

// MySQLConfig holds MySQL connection parameters.
type MySQLConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	Database string `json:"database"`
}

// LoggerConfig holds logger configuration.
type LoggerConfig struct {
	Level      string `json:"level"`
	Filename   string `json:"filename"`
	MaxSize    int    `json:"max_size"`
	MaxBackups int    `json:"max_backups"`
	MaxAge     int    `json:"max_age"`
	Compress   bool   `json:"compress"`
	Console    bool   `json:"console"`
}

// DefaultConfig returns a sensible default configuration.
func DefaultConfig() *Config {
	return &Config{
		ePDG: ePDGConfig{
			FQDN:       "epdg.example.com",
			PublicIP:   "0.0.0.0",
			InternalIP: "127.0.0.1",
			PLMN:       "46000",
			CertFile:   "./cert/server.pem",
			KeyFile:    "./cert/server.key",
			CAFile:     "./cert/ca.crt",
		},
		IKE: IKEConfig{
			ListenAddr:     ":500",
			NATTListenAddr: ":4500",
			SALifetime:     86400 * time.Second,
			ChildSALifetime: 3600 * time.Second,
			DPDInterval:    30 * time.Second,
			DPDTimeout:     120 * time.Second,
			ReauthTime:     3600 * time.Second,
			Proposals: []IKEProposal{
				{
					EncAlg:   "AES_CBC_256",
					IntegAlg: "HMAC_SHA2_256_128",
					PRFAlg:   "PRF_HMAC_SHA2_256",
					DHGroup:  "MODP_2048",
				},
				{
					EncAlg:   "AES_GCM_16_256",
					PRFAlg:   "PRF_HMAC_SHA2_256",
					DHGroup:  "ECP_256",
				},
			},
			ChildProposals: []IKEProposal{
				{
					EncAlg:   "AES_CBC_256",
					IntegAlg: "HMAC_SHA2_256_128",
					DHGroup:  "MODP_2048",
					ESNEnabled: false,
				},
			},
		},
		EAP: EAPConfig{
			Method:     "EAP-AKA-PRIME",
			MaxRetries: 3,
			Timeout:    30 * time.Second,
		},
		GTP: GTPConfig{
			ListenAddr: ":2152",
			PGWAddr:    "127.0.0.1:2152",
			BufferSize: 65535,
		},
		Diameter: DiameterConfig{
			Addr:             ":3868",
			AAAServerAddr:    "127.0.0.1:3868",
			OriginHost:       "epdg.example.com",
			OriginRealm:      "example.com",
			DestinationRealm: "example.com",
			TLSEnabled:       false,
			Timeout:          10 * time.Second,
			RetryCount:       3,
		},
		Database: DatabaseConfig{
			Type:       "sqlite",
			SQLitePath: "./data/epdg.db",
		},
		Logger: LoggerConfig{
			Level:      "info",
			Filename:   "./logs/epdg.log",
			MaxSize:    100,
			MaxBackups: 5,
			MaxAge:     7,
			Compress:   true,
			Console:    true,
		},
	}
}

// Load reads a JSON configuration file and returns a Config.
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read file %q: %w", path, err)
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("config: parse JSON: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config: validation: %w", err)
	}
	return cfg, nil
}

// Validate checks that required fields are set.
func (c *Config) Validate() error {
	if c.ePDG.PublicIP == "" {
		return fmt.Errorf("epdg.public_ip is required")
	}
	if c.ePDG.CertFile == "" || c.ePDG.KeyFile == "" {
		return fmt.Errorf("epdg.cert_file and epdg.key_file are required")
	}
	if c.IKE.ListenAddr == "" {
		return fmt.Errorf("ike.listen_addr is required")
	}
	if c.Diameter.AAAServerAddr == "" {
		return fmt.Errorf("diameter.aaa_server_addr is required")
	}
	return nil
}

// GetePDG returns the ePDG node configuration.
func (c *Config) GetePDG() ePDGConfig { return c.ePDG }

// GetIKE returns the IKEv2 configuration.
func (c *Config) GetIKE() IKEConfig { return c.IKE }

// GetEAP returns the EAP configuration.
func (c *Config) GetEAP() EAPConfig { return c.EAP }

// GetGTP returns the GTP-U configuration.
func (c *Config) GetGTP() GTPConfig { return c.GTP }

// GetDiameter returns the Diameter configuration.
func (c *Config) GetDiameter() DiameterConfig { return c.Diameter }

// GetDatabase returns the database configuration.
func (c *Config) GetDatabase() DatabaseConfig { return c.Database }

// GetLogger returns the logger configuration.
func (c *Config) GetLogger() LoggerConfig { return c.Logger }
