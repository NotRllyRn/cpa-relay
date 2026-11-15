// Package relay implements the bounded Codex access-token relay protocol.
package relay

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

const SnapshotPath = "/v0/resource/plugins/cpa-relay/snapshot"
const ReadyPath = "/v0/resource/plugins/cpa-relay/ready"
const MaxBody = 2 << 20
const MaxAccounts = 128

var ErrConfig = errors.New("invalid relay settings")
var ErrLegacyConfig = errors.New("accounts/source_files removed: drain old receiver and explicitly migrate to automatic Codex discovery with new private state")
var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
var envPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
var credentialPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var ownerPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

type Config struct {
	Enabled           bool   `yaml:"enabled"`
	Priority          int    `yaml:"priority"`
	Role              string `yaml:"role"`
	Endpoint          string `yaml:"endpoint"`
	SecretEnv         string `yaml:"secret_env"`
	PollSeconds       int    `yaml:"poll_seconds"`
	MaxStaleSeconds   int    `yaml:"max_stale_seconds"`
	ExpirySkewSeconds int    `yaml:"expiry_skew_seconds"`
	StateDir          string `yaml:"state_dir"`
	AuthDir           string `yaml:"auth_dir"`
	ReceiverID        string `yaml:"receiver_id"`
}

func ParseConfig(raw []byte) (Config, string, error) {
	c := Config{PollSeconds: 15, MaxStaleSeconds: 3600, ExpirySkewSeconds: 60}
	var node yaml.Node
	if yaml.Unmarshal(raw, &node) != nil {
		return c, "", ErrConfig
	}
	if len(node.Content) == 1 && node.Content[0].Kind == yaml.MappingNode {
		fields := node.Content[0].Content
		for i := 0; i+1 < len(fields); i += 2 {
			if fields[i].Value == "accounts" || fields[i].Value == "source_files" {
				return c, "", ErrLegacyConfig
			}
		}
	}
	d := yaml.NewDecoder(bytes.NewReader(raw))
	d.KnownFields(true)
	if d.Decode(&c) != nil {
		return c, "", ErrConfig
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return c, "", ErrConfig
	}
	if c.Role != "exporter" && c.Role != "receiver" {
		return c, "", ErrConfig
	}
	if !envPattern.MatchString(c.SecretEnv) || !filepath.IsAbs(c.StateDir) || filepath.Clean(c.StateDir) != c.StateDir {
		return c, "", ErrConfig
	}
	if c.PollSeconds < 1 || c.PollSeconds > 300 || c.MaxStaleSeconds < c.PollSeconds*2 || c.MaxStaleSeconds > 86400 || c.ExpirySkewSeconds < 5 || c.ExpirySkewSeconds > 600 {
		return c, "", ErrConfig
	}
	if c.Role == "receiver" {
		u, e := url.Parse(c.Endpoint)
		if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != SnapshotPath || u.RawPath != "" || u.Opaque != "" || u.ForceQuery {
			return c, "", ErrConfig
		}
		if !filepath.IsAbs(c.AuthDir) || filepath.Clean(c.AuthDir) != c.AuthDir || within(c.StateDir, c.AuthDir) || within(c.AuthDir, c.StateDir) || !ownerPattern.MatchString(c.ReceiverID) {
			return c, "", ErrConfig
		}
	} else if c.Endpoint != "" || c.AuthDir != "" || c.ReceiverID != "" {
		return c, "", ErrConfig
	}
	secret := os.Getenv(c.SecretEnv)
	decoded, e := base64.RawURLEncoding.DecodeString(secret)
	if e != nil || len(decoded) < 32 || len(decoded) > 128 || strings.TrimSpace(secret) != secret {
		return c, "", ErrConfig
	}
	return c, secret, nil
}

func within(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// Binding prevents a cache/watermark from silently changing authority or namespace.
func (c Config) binding() string {
	sum := sha256.Sum256([]byte(strings.Join([]string{"cpa-relay/state/v2", c.Role, c.Endpoint, c.AuthDir, c.ReceiverID}, "\x00")))
	return hex.EncodeToString(sum[:])
}
