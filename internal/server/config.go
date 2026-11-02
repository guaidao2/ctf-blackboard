package server

import (
	"fmt"
	"log/slog"
	"strings"
	"time"
)

var Version = "1.0.0"

// Config is the server's startup configuration. The one shared password is
// deliberately kept out of structs that get logged.
type Config struct {
	Listen          string
	DataDir         string
	Password        string
	ServerName      string
	Motd            string
	SlotLimit       int
	TotalChallenges int
	PublicURL       string
	CertFile        string
	KeyFile         string
	Logger          *slog.Logger

	HandshakeTimeout time.Duration
	KickCooldown     time.Duration
	MaxChatHistory   int
	MaxActivity      int
	MaxWriteupBytes  int
}

func (c *Config) normalize() error {
	if strings.TrimSpace(c.DataDir) == "" {
		c.DataDir = "./data"
	}
	if strings.TrimSpace(c.Listen) == "" {
		c.Listen = "0.0.0.0:8443"
	}
	if strings.TrimSpace(c.ServerName) == "" {
		c.ServerName = "CTF Blackboard"
	}
	if c.SlotLimit < 0 {
		return fmt.Errorf("--slots cannot be negative")
	}
	if c.TotalChallenges < 0 {
		return fmt.Errorf("--total cannot be negative")
	}
	if (c.CertFile == "") != (c.KeyFile == "") {
		return fmt.Errorf("--cert and --key must be provided together")
	}
	if c.Password == "" {
		return fmt.Errorf("server password is required")
	}
	if len([]rune(c.Password)) < 12 {
		return fmt.Errorf("server password must be at least 12 characters")
	}
	if c.HandshakeTimeout <= 0 {
		c.HandshakeTimeout = 15 * time.Second
	}
	if c.KickCooldown <= 0 {
		c.KickCooldown = 2 * time.Minute
	}
	if c.MaxChatHistory <= 0 {
		c.MaxChatHistory = 2000
	}
	if c.MaxActivity <= 0 {
		c.MaxActivity = 1000
	}
	if c.MaxWriteupBytes <= 0 {
		c.MaxWriteupBytes = 256 << 10
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	return nil
}
