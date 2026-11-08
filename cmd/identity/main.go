// Command identity is the account service for vif: registration, sign-in by
// Argon2-SCRAM, sign-ins per device and their revocation on /vif/api/auth/,
// and on a second loopback listener the router's one question, which account
// a token names. Accounts live in PostgreSQL, or in one file for a small
// deployment, as verifiers, never passwords; identity migrate and identity
// account are the operator's commands on them.
package main

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/lixenwraith/identity/internal/api"
	"github.com/lixenwraith/identity/internal/config"
	"github.com/lixenwraith/identity/internal/introspect"
	"github.com/lixenwraith/identity/internal/pg"
	"github.com/lixenwraith/identity/internal/store"
	"github.com/lixenwraith/identity/internal/version"

	"github.com/lixenwraith/auth"
)

const (
	decoyKeyFile  = "decoy.key"
	decoyKeyBytes = 32
	openTimeout   = 15 * time.Second
	stopTimeout   = 15 * time.Second
	sweepInterval = time.Hour
)

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "migrate" || os.Args[1] == "account") {
		err := cli(context.Background(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
		switch {
		case errors.Is(err, flag.ErrHelp):
			os.Exit(0)
		case errors.Is(err, errUsage):
			os.Exit(2)
		case err != nil:
			fmt.Fprintf(os.Stderr, "%s: %v\n", config.Name, err)
			os.Exit(1)
		}
		return
	}
	cfg, err := config.Parse(os.Args[1:], os.Stderr)
	switch {
	case errors.Is(err, flag.ErrHelp):
		os.Exit(0)
	case err != nil:
		fmt.Fprintf(os.Stderr, "%s: %v\n", config.Name, err)
		os.Exit(2)
	case cfg.Version:
		fmt.Println(version.String())
		return
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	if err := run(context.Background(), cfg, logger); err != nil {
		logger.Error("identity stopped", "error", err)
		os.Exit(1)
	}
}

// database is the pool's configuration from the flags: the password read from
// its file, the server verified against the CA file or the system roots.
func database(cfg config.Config) (pg.Config, error) {
	dbCfg, err := pg.ParseURL(cfg.DatabaseURL)
	if err != nil {
		return pg.Config{}, err
	}
	password, err := config.ReadSecretFile(cfg.DBPasswordFile)
	if err != nil {
		return pg.Config{}, fmt.Errorf("database password: %w", err)
	}
	dbCfg.Password = string(password)
	clear(password)
	var ca []byte
	if cfg.DBCAFile != "" {
		if ca, err = os.ReadFile(cfg.DBCAFile); err != nil {
			return pg.Config{}, fmt.Errorf("database CA: %w", err)
		}
	}
	if dbCfg.TLS, err = pg.TLSConfig(ca, dbCfg.Host); err != nil {
		return pg.Config{}, err
	}
	dbCfg.MaxConns = cfg.DBPool
	return dbCfg, nil
}

// openStore is the configured store: the file -store-file names, held for the
// process's life, or PostgreSQL through a pool; close releases either. A command
// that only reads takes the file without its lock, so it runs beside the service.
func openStore(ctx context.Context, cfg config.Config, readOnly bool) (store.Store, func(), error) {
	if cfg.StoreFile != "" {
		f, err := store.OpenFile(cfg.StoreFile, readOnly)
		if err != nil {
			return nil, nil, err
		}
		return f, func() { _ = f.Close() }, nil
	}
	dbCfg, err := database(cfg)
	if err != nil {
		return nil, nil, err
	}
	openCtx, cancel := context.WithTimeout(ctx, openTimeout)
	pool, err := pg.Open(openCtx, dbCfg)
	cancel()
	if err != nil {
		return nil, nil, fmt.Errorf("database: %w", err)
	}
	return store.NewPG(pool), func() { _ = pool.Close() }, nil
}

func run(ctx context.Context, cfg config.Config, logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	key, err := decoyKey(cfg.StateDir)
	if err != nil {
		return err
	}
	scram, err := auth.NewScramServerWithDecoyKey(key)
	clear(key)
	if err != nil {
		return err
	}
	defer scram.Stop()

	st, closeStore, err := openStore(ctx, cfg, false)
	if err != nil {
		return err
	}
	defer closeStore()
	if err := st.CheckSchema(ctx); err != nil {
		return err
	}
	// Every verifier is loaded before a request is answered, so an unknown name
	// and a known one take the same path from the first sign-in on; one derived
	// under another profile would split the population, so it stops the start.
	verifiers, err := st.Verifiers(ctx)
	if err != nil {
		return fmt.Errorf("load verifiers: %w", err)
	}
	for _, v := range verifiers {
		if k := cfg.KDF; v.ArgonMemory != k.Memory || v.ArgonTime != k.Time || v.ArgonThreads != k.Threads {
			return fmt.Errorf("verifier of %q was derived under another KDF profile (%d KiB, %d passes, %d lanes); the service runs one",
				v.Name, v.ArgonMemory, v.ArgonTime, v.ArgonThreads)
		}
		if err := scram.AddCredential(v.Credential()); err != nil {
			return fmt.Errorf("verifier of %q: %w", v.Name, err)
		}
	}
	go sweep(ctx, st, logger)

	handler := api.New(api.Options{
		Store: st, Scram: scram, KDF: cfg.KDF, MaxAccounts: cfg.MaxAccounts,
		ClientAddressHeader: cfg.ClientAddressHeader, Logger: logger,
	})
	asker := introspect.New(st, logger)
	// Bound here rather than inside Serve, so a port already taken is an error
	// this returns, and the log line below names two sockets that exist.
	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.Listen, err)
	}
	introListener, err := net.Listen("tcp", cfg.IntrospectListen)
	if err != nil {
		_ = listener.Close()
		return fmt.Errorf("listen on %s: %w", cfg.IntrospectListen, err)
	}
	servers := []*http.Server{
		newServer(ctx, handler, api.ExchangeTimeout),
		newServer(ctx, asker, introspect.Timeout),
	}
	errCh := make(chan error, len(servers))
	go func() { errCh <- servers[0].Serve(listener) }()
	go func() { errCh <- servers[1].Serve(introListener) }()
	logger.Info("identity listening", "listen", cfg.Listen, "introspect", cfg.IntrospectListen,
		"accounts", len(verifiers), "store", cmp.Or(cfg.StoreFile, "postgresql"), "version", version.String())

	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), stopTimeout)
	defer cancel()
	for _, server := range servers {
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("HTTP shutdown: %w", err)
		}
	}
	return nil
}

// sweep deletes expired sign-ins once an hour: no lookup finds them, so this
// is housekeeping, and the count at info says how the table breathes.
func sweep(ctx context.Context, st store.Store, logger *slog.Logger) {
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		sweepCtx, cancel := context.WithTimeout(ctx, time.Minute)
		n, err := st.DeleteExpiredSignIns(sweepCtx)
		cancel()
		switch {
		case err != nil:
			logger.Error("sweep of expired sign-ins failed", "error", err)
		case n > 0:
			logger.Info("expired sign-ins deleted", "count", n)
		}
	}
}

func newServer(ctx context.Context, handler http.Handler, timeout time.Duration) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       timeout,
		WriteTimeout:      timeout,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
}

// decoyKey is the SCRAM server's key for an unknown name's challenge, made
// once and kept 0600 in the state directory, so a probe sees the same salt
// across restarts and cannot tell an account from none.
func decoyKey(dir string) ([]byte, error) {
	path := filepath.Join(dir, decoyKeyFile)
	encoded, err := config.ReadSecretFile(path)
	switch {
	case err == nil:
		key, err := base64.StdEncoding.Strict().DecodeString(string(encoded))
		if err != nil || len(key) < decoyKeyBytes {
			return nil, fmt.Errorf("%s does not hold a base64 key of %d bytes", path, decoyKeyBytes)
		}
		return key, nil
	case !errors.Is(err, os.ErrNotExist):
		return nil, fmt.Errorf("decoy key: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	key := make([]byte, decoyKeyBytes)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("decoy key: %w", err)
	}
	if _, err := f.WriteString(base64.StdEncoding.EncodeToString(key) + "\n"); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return key, nil
}
