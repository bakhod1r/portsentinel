// Package config loads and validates PortSentinel configuration.
package config

import (
	"errors"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Mode controls how far PortSentinel goes after discovery.
type Mode string

const (
	ModeAudit   Mode = "audit"
	ModeDryRun  Mode = "dry-run"
	ModeEnforce Mode = "enforce"
	ModeMonitor Mode = "monitor"
)

// Exception temporarily allows a port until Expires.
type Exception struct {
	Port    int       `yaml:"port"`
	Proto   string    `yaml:"proto"`
	Reason  string    `yaml:"reason"`
	Expires time.Time `yaml:"expires"`
}

// PortRange is an inclusive range of allowed ports.
type PortRange struct {
	From int `yaml:"from"`
	To   int `yaml:"to"`
}

// Policy describes what may stay exposed.
type Policy struct {
	AllowedTCP      []int       `yaml:"allowed_tcp"`
	AllowedRanges   []PortRange `yaml:"allowed_ranges"`
	ManagementPorts []int       `yaml:"management_ports"`
	SSHPort         int         `yaml:"ssh_port"`
	AllowedSources  []string    `yaml:"allowed_sources"`
	Exceptions      []Exception `yaml:"exceptions"`
}

// Scan holds probe settings.
type Scan struct {
	Ports       string        `yaml:"ports"` // e.g. "1-1024,3306,5432,8080"
	Timeout     time.Duration `yaml:"timeout"`
	Concurrency int           `yaml:"concurrency"`
	Interval    time.Duration `yaml:"interval"`
	Banner      bool          `yaml:"banner"`
}

// Config is the root configuration document.
type Config struct {
	Targets         []string      `yaml:"targets"`
	Mode            Mode          `yaml:"mode"`
	Backend         string        `yaml:"backend"`
	StateDir        string        `yaml:"state_dir"`
	AuditLog        string        `yaml:"audit_log"`
	RollbackTimeout time.Duration `yaml:"rollback_timeout"`
	Scan            Scan          `yaml:"scan"`
	Policy          Policy        `yaml:"policy"`
}

// Default returns a safe audit-only configuration.
func Default() *Config {
	return &Config{
		Targets:         []string{"127.0.0.1"},
		Mode:            ModeAudit,
		Backend:         "nftables",
		StateDir:        "/var/lib/portsentinel",
		AuditLog:        "/var/log/portsentinel/audit.jsonl",
		RollbackTimeout: 60 * time.Second,
		Scan: Scan{
			Ports:       "1-1024,3000,3306,5432,6379,8000,8080,8443,9200,27017",
			Timeout:     800 * time.Millisecond,
			Concurrency: 256,
			Interval:    15 * time.Minute,
			Banner:      true,
		},
		Policy: Policy{
			AllowedTCP: []int{22, 80, 443},
			SSHPort:    22,
		},
	}
}

// Load reads a YAML file on top of defaults and validates it.
func Load(path string) (*Config, error) {
	cfg := Default()
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return cfg, cfg.Validate()
}

// Validate checks the configuration for unsafe or inconsistent values.
func (c *Config) Validate() error {
	var errs []error
	if len(c.Targets) == 0 {
		errs = append(errs, errors.New("targets: at least one authorized target is required"))
	}
	switch c.Mode {
	case ModeAudit, ModeDryRun, ModeEnforce, ModeMonitor:
	default:
		errs = append(errs, fmt.Errorf("mode: unknown %q", c.Mode))
	}
	if c.Backend != "nftables" {
		errs = append(errs, fmt.Errorf("backend: %q not supported yet (nftables only)", c.Backend))
	}
	if c.Policy.SSHPort < 1 || c.Policy.SSHPort > 65535 {
		errs = append(errs, errors.New("policy.ssh_port: must be 1-65535"))
	}
	if _, err := ParsePorts(c.Scan.Ports); err != nil {
		errs = append(errs, fmt.Errorf("scan.ports: %w", err))
	}
	if c.Scan.Timeout <= 0 || c.Scan.Concurrency <= 0 {
		errs = append(errs, errors.New("scan: timeout and concurrency must be positive"))
	}
	for _, r := range c.Policy.AllowedRanges {
		if r.From < 1 || r.To > 65535 || r.From > r.To {
			errs = append(errs, fmt.Errorf("policy.allowed_ranges: invalid %d-%d", r.From, r.To))
		}
	}
	return errors.Join(errs...)
}

// Save writes the configuration as YAML.
func (c *Config) Save(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
