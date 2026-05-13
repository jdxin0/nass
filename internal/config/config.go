package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Server       Server       `toml:"server"`
	TLS          TLS          `toml:"tls"`
	DB           DB           `toml:"db"`
	OIDC         OIDC         `toml:"oidc"`
	Portal       Portal       `toml:"portal"`
	Orchestrator Orchestrator `toml:"orchestrator"`

	path string
}

type Server struct {
	HTTPSAddr string `toml:"https_addr"`
	HTTPAddr  string `toml:"http_addr"`
	BaseHost  string `toml:"base_host"`
}

type TLS struct {
	CertFile string `toml:"cert_file"`
	KeyFile  string `toml:"key_file"`
}

type DB struct {
	Path string `toml:"path"`
}

type OIDC struct {
	Issuer        string `toml:"issuer"`
	Subdomain     string `toml:"subdomain"`
	KeyFile       string `toml:"key_file"`
	CryptoKeyFile string `toml:"crypto_key_file"`
}

type Portal struct {
	Title     string `toml:"title"`
	Subdomain string `toml:"subdomain"`
}

type Orchestrator struct {
	DataRoot         string `toml:"data_root"`
	ComposeRoot      string `toml:"compose_root"`
	DockerCompose    string `toml:"docker_compose"`
	BackendPortRange string `toml:"backend_port_range"`
}

func Default() *Config {
	return &Config{
		Server: Server{
			HTTPSAddr: ":443",
			HTTPAddr:  ":80",
		},
		OIDC: OIDC{
			Subdomain:     "auth",
			KeyFile:       "oidc.key",
			CryptoKeyFile: "oidc-crypto.key",
		},
		Portal: Portal{
			Title: "nass",
		},
		DB: DB{Path: "nass.db"},
		Orchestrator: Orchestrator{
			DockerCompose:    "docker compose",
			BackendPortRange: "20000-29999",
		},
	}
}

func Load(path string) (*Config, error) {
	c := Default()
	if _, err := toml.DecodeFile(path, c); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	c.path = path
	if err := c.resolvePaths(); err != nil {
		return nil, err
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	if c.OIDC.Issuer == "" && c.Server.BaseHost != "" {
		c.OIDC.Issuer = "https://" + c.OIDC.Subdomain + "." + c.Server.BaseHost
	}
	return c, nil
}

func (c *Config) Path() string { return c.path }

func (c *Config) resolvePaths() error {
	base, err := filepath.Abs(filepath.Dir(c.path))
	if err != nil {
		return err
	}
	rel := func(p *string) {
		if *p != "" && !filepath.IsAbs(*p) {
			*p = filepath.Join(base, *p)
		}
	}
	rel(&c.DB.Path)
	rel(&c.OIDC.KeyFile)
	rel(&c.OIDC.CryptoKeyFile)
	rel(&c.TLS.CertFile)
	rel(&c.TLS.KeyFile)
	rel(&c.Orchestrator.DataRoot)
	rel(&c.Orchestrator.ComposeRoot)
	return nil
}

func (c *Config) validate() error {
	if c.Server.BaseHost == "" {
		return fmt.Errorf("server.base_host is required")
	}
	if c.DB.Path == "" {
		return fmt.Errorf("db.path is required")
	}
	return nil
}

// Write serializes the config to disk. Used by `nass init`.
func Write(path string, c *Config) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists", path)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	return toml.NewEncoder(f).Encode(c)
}
