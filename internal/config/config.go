// Package config reads the service's flags, which the unit renders from its
// environment file, into one checked Config: where the two loopback listeners
// bind, the state directory, the database and the KDF profile every account
// shares. A secret is named by a file here and read by ReadSecretFile.
package config

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/lixenwraith/identity/internal/pg"

	"github.com/lixenwraith/auth"
)

const (
	Name = "identity"
	// DefaultStateDir is where the decoy key lives when systemd names no StateDirectory.
	DefaultStateDir = "/var/lib/identity"
	maxSecretBytes  = 4096
)

var headerPattern = regexp.MustCompile(`^[A-Za-z0-9][-A-Za-z0-9]*$`)

// KDF is the one Argon2id profile every account's credential is derived
// under: a mixed population would tell a prober which accounts exist.
type KDF struct {
	Memory  uint32 // KiB
	Time    uint32
	Threads uint8
}

type Config struct {
	Listen              string
	IntrospectListen    string
	StateDir            string
	DatabaseURL         string
	DBPasswordFile      string
	DBCAFile            string
	DBPool              int
	LogLevel            slog.Level
	MaxAccounts         int
	ClientAddressHeader string
	KDF                 KDF
	Version             bool
}

// Parse reads args as the service's flags. Help and a usage error return as
// flag's own errors, printed to output, so the caller only exits.
func Parse(args []string, output io.Writer) (Config, error) {
	var cfg Config
	var logLevel string
	var kdfTime, kdfMemory, kdfThreads uint
	set := flag.NewFlagSet(Name, flag.ContinueOnError)
	set.SetOutput(output)
	set.Usage = func() {
		fmt.Fprintf(output, "Usage: %s [flags]\n       %s migrate [flags]\n       %s account add|disable|enable|reset|list|delete [<name>] [flags]\n\n"+
			"The account service: /vif/api/auth/ for the router to forward, and the router's\n"+
			"introspection, both on loopback. Accounts live in PostgreSQL; migrate and account\n"+
			"are the operator's commands on them, with the same database flags.\n\nFlags:\n", Name, Name, Name)
		set.PrintDefaults()
	}
	set.StringVar(&cfg.Listen, "listen", "127.0.0.1:9082", "the /vif/api/auth/ listener the router forwards to (loopback)")
	set.StringVar(&cfg.IntrospectListen, "introspect-listen", "127.0.0.1:9083",
		"the introspection listener the router asks which account a token names (loopback)")
	set.StringVar(&cfg.StateDir, "state-dir", defaultStateDir(), "directory of the decoy key, 0700")
	set.StringVar(&cfg.DatabaseURL, "db-url", "",
		"postgres://user@host[:port]/database[?sslmode=verify-full], without a password (required)")
	set.StringVar(&cfg.DBPasswordFile, "db-password-file", "", "0600 file holding the database role's password (required)")
	set.StringVar(&cfg.DBCAFile, "db-ca-file", "",
		"PEM certificate the database is verified against: the server's own or its issuer's; empty trusts the system roots")
	set.IntVar(&cfg.DBPool, "db-pool", pg.DefaultMaxConns, "database connections held at most (1 to 64)")
	set.StringVar(&logLevel, "log-level", "info", "debug, info, warn or error")
	set.IntVar(&cfg.MaxAccounts, "max-accounts", 0, "accounts at which registration closes; 0 leaves no cap")
	set.StringVar(&cfg.ClientAddressHeader, "client-address-header", "X-Real-IP",
		"header the router forwards the player's address in, believed from a loopback peer alone; empty budgets the peer")
	set.UintVar(&kdfMemory, "kdf-memory", auth.DefaultArgonMemory, "Argon2id memory in KiB every credential is derived with")
	set.UintVar(&kdfTime, "kdf-time", auth.DefaultArgonTime, "Argon2id passes every credential is derived with")
	set.UintVar(&kdfThreads, "kdf-threads", auth.DefaultArgonThreads, "Argon2id lanes every credential is derived with")
	set.BoolVar(&cfg.Version, "version", false, "print the version and exit")
	if err := set.Parse(dropEmptyFlags(args)); err != nil {
		return Config{}, err
	}
	if set.NArg() != 0 {
		return Config{}, fmt.Errorf("unexpected argument %q", set.Arg(0))
	}
	if err := cfg.LogLevel.UnmarshalText([]byte(logLevel)); err != nil || !strings.EqualFold(cfg.LogLevel.String(), logLevel) {
		return Config{}, fmt.Errorf("-log-level %q must be debug, info, warn or error", logLevel)
	}
	if kdfMemory > 1<<32-1 || kdfTime > 1<<32-1 || kdfThreads > 255 {
		return Config{}, errors.New("-kdf-memory, -kdf-time and -kdf-threads are out of range")
	}
	cfg.KDF = KDF{Memory: uint32(kdfMemory), Time: uint32(kdfTime), Threads: uint8(kdfThreads)}
	if cfg.Version {
		return cfg, nil
	}
	return cfg, cfg.Validate()
}

// defaultStateDir is systemd's StateDirectory when the unit set one, so the
// unit need not repeat the path as a flag.
func defaultStateDir() string {
	if dir := os.Getenv("STATE_DIRECTORY"); dir != "" {
		return dir
	}
	return DefaultStateDir
}

// dropEmptyFlags removes flags whose value is empty, so the flag's own default
// applies instead. systemd expands a variable the environment file does not
// define to an empty argument, which would override a default with nothing or
// fail to parse. A flag that is required still fails, by name.
func dropEmptyFlags(args []string) []string {
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		switch {
		case strings.HasSuffix(args[i], "=") && strings.HasPrefix(args[i], "-"):
		case strings.HasPrefix(args[i], "-") && i+1 < len(args) && args[i+1] == "":
			i++
		default:
			out = append(out, args[i])
		}
	}
	return out
}

func (c Config) Validate() error {
	for name, addr := range map[string]string{"-listen": c.Listen, "-introspect-listen": c.IntrospectListen} {
		if err := loopback(addr); err != nil {
			return fmt.Errorf("%s %q: %w", name, addr, err)
		}
	}
	if c.Listen == c.IntrospectListen {
		return errors.New("-listen and -introspect-listen must differ: the forward must never reach introspection")
	}
	if !filepath.IsAbs(c.StateDir) {
		return fmt.Errorf("-state-dir %q must be an absolute path", c.StateDir)
	}
	if c.DatabaseURL == "" {
		return errors.New("-db-url is required")
	}
	if _, err := pg.ParseURL(c.DatabaseURL); err != nil {
		return fmt.Errorf("-db-url: %w", err)
	}
	if c.DBPasswordFile == "" {
		return errors.New("-db-password-file is required")
	}
	if c.DBPool < 1 || c.DBPool > 64 {
		return fmt.Errorf("-db-pool %d must be 1 to 64", c.DBPool)
	}
	if c.MaxAccounts < 0 {
		return fmt.Errorf("-max-accounts %d must not be negative", c.MaxAccounts)
	}
	if h := c.ClientAddressHeader; h != "" && !headerPattern.MatchString(h) {
		return fmt.Errorf("invalid -client-address-header %q", h)
	}
	return c.KDF.check()
}

// check holds the profile within what auth will verify: a credential derived
// outside it could be stored and never proven.
func (k KDF) check() error {
	switch {
	case k.Time == 0 || k.Threads == 0 || k.Memory < 8*uint32(k.Threads):
		return errors.New("the KDF profile needs at least one pass, one lane and 8 KiB a lane")
	case k.Memory > auth.MaxVerifyArgonMemory, k.Time > auth.MaxVerifyArgonTime, k.Threads > auth.MaxVerifyArgonThreads,
		uint64(k.Memory)*uint64(k.Time) > auth.MaxVerifyArgonWork:
		return fmt.Errorf("the KDF profile exceeds what auth verifies: %d KiB, %d passes, %d lanes",
			auth.MaxVerifyArgonMemory, auth.MaxVerifyArgonTime, auth.MaxVerifyArgonThreads)
	}
	return nil
}

// loopback admits host:port whose host is a loopback IP literal: the router is
// the only caller, and a name could resolve elsewhere later.
func loopback(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return errors.New("must be host:port")
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return errors.New("must bind a loopback IP address")
	}
	if port == "" || port == "0" {
		return errors.New("must name a port")
	}
	return nil
}

// ReadSecretFile reads a secret the way an SSH key is read: a regular file
// that group and others cannot open, trailing line breaks dropped so a file
// an editor or `openssl rand` wrote works as it is.
func ReadSecretFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("%s has mode %04o; group and others must have no access (chmod 600)", path, perm)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxSecretBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxSecretBytes {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, maxSecretBytes)
	}
	secret := bytes.TrimRight(data, "\r\n")
	if len(secret) == 0 {
		return nil, fmt.Errorf("%s is empty", path)
	}
	return secret, nil
}
