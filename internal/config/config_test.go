package config

import (
	"bytes"
	"errors"
	"flag"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/lixenwraith/auth"
)

var required = []string{"-db-url", "postgres://identity@db.example.test/identity", "-db-password-file", "/etc/identity/db-password"}

func TestTheDefaultsAreTheDesigns(t *testing.T) {
	t.Setenv("STATE_DIRECTORY", "")
	cfg, err := Parse(required, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:9082" || cfg.IntrospectListen != "127.0.0.1:9083" || cfg.StateDir != DefaultStateDir ||
		cfg.DBPool != 10 || cfg.LogLevel != slog.LevelInfo || cfg.MaxAccounts != 0 || cfg.ClientAddressHeader != "X-Real-IP" {
		t.Fatalf("defaults: %+v", cfg)
	}
	if cfg.KDF != (KDF{Memory: auth.DefaultArgonMemory, Time: auth.DefaultArgonTime, Threads: auth.DefaultArgonThreads}) {
		t.Fatalf("KDF profile: %+v", cfg.KDF)
	}
	t.Setenv("STATE_DIRECTORY", "/var/lib/other")
	if cfg, err := Parse(required, &bytes.Buffer{}); err != nil || cfg.StateDir != "/var/lib/other" {
		t.Fatalf("systemd's StateDirectory was not taken: %+v, %v", cfg, err)
	}
}

func TestHelpPrintsEveryFlag(t *testing.T) {
	var out bytes.Buffer
	if _, err := Parse([]string{"-h"}, &out); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("-h: %v", err)
	}
	for _, flag := range []string{"-listen", "-introspect-listen", "-state-dir", "-db-url", "-db-password-file",
		"-db-ca-file", "-db-pool", "-log-level", "-max-accounts", "-client-address-header", "-kdf-memory", "-version"} {
		if !strings.Contains(out.String(), flag+" ") && !strings.Contains(out.String(), flag+"\n") {
			t.Errorf("usage lacks %s", flag)
		}
	}
	if cfg, err := Parse([]string{"-version"}, &bytes.Buffer{}); err != nil || !cfg.Version {
		t.Fatalf("-version needs no database: %v", err)
	}
}

func TestAListenerBindsLoopbackAlone(t *testing.T) {
	for _, args := range [][]string{
		{"-listen", "0.0.0.0:9082"},
		{"-listen", ":9082"},
		{"-listen", "localhost:9082"},
		{"-listen", "127.0.0.1"},
		{"-listen", "127.0.0.1:0"},
		{"-introspect-listen", "10.0.0.1:9083"},
		{"-introspect-listen", "127.0.0.1:9082"},
	} {
		if _, err := Parse(slices.Concat(required, args), &bytes.Buffer{}); err == nil {
			t.Errorf("%v was accepted", args)
		}
	}
	if _, err := Parse(slices.Concat(required, []string{"-listen", "[::1]:9082"}), &bytes.Buffer{}); err != nil {
		t.Fatalf("IPv6 loopback refused: %v", err)
	}
}

func TestASettingIsRefusedByName(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"-db-password-file", "/x"}, "-db-url is required"},
		{[]string{"-db-url", "postgres://identity:pw@db.example.test/identity", "-db-password-file", "/x"}, "-db-url:"},
		{[]string{"-db-url", "postgres://identity@db.example.test/identity"}, "-db-password-file is required"},
		{slices.Concat(required, []string{"-db-pool", "0"}), "-db-pool"},
		{slices.Concat(required, []string{"-log-level", "loud"}), "-log-level"},
		{slices.Concat(required, []string{"-max-accounts", "-1"}), "-max-accounts"},
		{slices.Concat(required, []string{"-client-address-header", "X Real IP"}), "-client-address-header"},
		{slices.Concat(required, []string{"-state-dir", "state"}), "-state-dir"},
		{slices.Concat(required, []string{"-kdf-memory", "16", "-kdf-threads", "4"}), "KDF profile"},
		{slices.Concat(required, []string{"-kdf-time", "17"}), "KDF profile"},
		{slices.Concat(required, []string{"extra"}), "unexpected argument"},
	} {
		_, err := Parse(tc.args, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: got %v, want an error naming %q", tc.args, err, tc.want)
		}
	}
}

// A variable the unit's environment file leaves unset reaches the flag empty.
func TestAnEmptyValueIsTheDefault(t *testing.T) {
	args := slices.Concat(required, []string{"-db-pool", "", "-log-level=", "-max-accounts", "7"})
	cfg, err := Parse(args, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DBPool != 10 || cfg.LogLevel != slog.LevelInfo || cfg.MaxAccounts != 7 {
		t.Fatalf("empty values did not take the defaults: %+v", cfg)
	}
}

func TestASecretFileIsPrivateAndTrimmed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	if err := os.WriteFile(path, []byte("hunter22\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadSecretFile(path)
	if err != nil || string(got) != "hunter22" {
		t.Fatalf("ReadSecretFile = %q, %v", got, err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSecretFile(path); err == nil {
		t.Fatal("a group-readable secret was read")
	}
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSecretFile(empty); err == nil {
		t.Fatal("an empty secret was read")
	}
	if _, err := ReadSecretFile(dir); err == nil {
		t.Fatal("a directory was read as a secret")
	}
}
