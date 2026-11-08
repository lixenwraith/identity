// Package pg is the service's own PostgreSQL client on the standard library:
// the version 3 wire protocol over TLS, SCRAM-SHA-256 SASL authentication, the
// simple and extended query protocols with text results and a small pool. A
// schema of three tables needs no more, and a driver's dozen modules would be
// the largest thing this service carries.
package pg

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/url"
	"time"
)

const (
	// DefaultMaxConns is the pool the budget counts: ten connections.
	DefaultMaxConns       = 10
	DefaultConnectTimeout = 5 * time.Second
	defaultPort           = "5432"
)

var (
	ErrNoRows         = errors.New("pg: no rows")
	ErrClosed         = errors.New("pg: pool is closed")
	ErrNotImplemented = errors.New("pg: the wire protocol is not implemented")
)

// Config is one server to connect to. The password comes from a 0600 file,
// never from the URL, so neither a command line nor a log line can carry it.
type Config struct {
	Host     string
	Port     string
	Database string
	User     string
	Password string
	// TLS is required: a hop over the host's internal network is still a hop.
	TLS            *tls.Config
	MaxConns       int
	ConnectTimeout time.Duration
}

// ParseURL reads postgres://user@host[:port]/database[?sslmode=verify-full].
// It refuses a password, any other sslmode and any other parameter: the
// password has a file, TLS has no weaker mode here, and an option this client
// does not read would otherwise be ignored in silence.
func ParseURL(raw string) (Config, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Config{}, errors.New("pg: malformed database URL")
	}
	if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		return Config{}, fmt.Errorf("pg: database URL scheme %q is not postgres", u.Scheme)
	}
	if u.User == nil || u.User.Username() == "" {
		return Config{}, errors.New("pg: database URL names no user")
	}
	if _, has := u.User.Password(); has {
		return Config{}, errors.New("pg: database URL carries a password; name a password file instead")
	}
	if u.Hostname() == "" {
		return Config{}, errors.New("pg: database URL names no host")
	}
	database := u.EscapedPath()
	if len(database) < 2 || database[0] != '/' {
		return Config{}, errors.New("pg: database URL names no database")
	}
	for key, values := range u.Query() {
		if key != "sslmode" || len(values) != 1 || values[0] != "verify-full" {
			return Config{}, fmt.Errorf("pg: database URL parameter %q is not accepted; only sslmode=verify-full is", key)
		}
	}
	if u.Fragment != "" || u.RawFragment != "" {
		return Config{}, errors.New("pg: database URL carries a fragment")
	}
	cfg := Config{
		Host:           u.Hostname(),
		Port:           u.Port(),
		Database:       database[1:],
		User:           u.User.Username(),
		MaxConns:       DefaultMaxConns,
		ConnectTimeout: DefaultConnectTimeout,
	}
	if cfg.Port == "" {
		cfg.Port = defaultPort
	}
	return cfg, nil
}

func (c Config) check() error {
	switch {
	case c.Host == "" || c.Port == "" || c.Database == "" || c.User == "":
		return errors.New("pg: host, port, database and user are required")
	case c.Password == "":
		return errors.New("pg: a password is required")
	case c.TLS == nil:
		return errors.New("pg: TLS is required")
	case c.MaxConns < 1:
		return errors.New("pg: the pool needs at least one connection")
	}
	return nil
}

// Pool hands out connections to one server, at most MaxConns at once, and
// retries nothing: a statement that failed is the caller's to repeat.
type Pool struct {
	cfg Config
}

// Open checks cfg and connects once, so a wrong password or an unverifiable
// certificate is refused at start and not on the first request.
func Open(ctx context.Context, cfg Config) (*Pool, error) {
	if err := cfg.check(); err != nil {
		return nil, err
	}
	return nil, ErrNotImplemented
}

func (p *Pool) Close() error {
	if p == nil {
		return nil
	}
	return ErrNotImplemented
}

// Exec runs one statement. Without arguments it goes as one simple query, so
// it may hold several statements, as a migration does; with arguments it is
// prepared and bound unnamed, so no value is ever spliced into SQL text.
func (p *Pool) Exec(ctx context.Context, sql string, args ...any) (Result, error) {
	return Result{}, ErrNotImplemented
}

func (p *Pool) Query(ctx context.Context, sql string, args ...any) (*Rows, error) {
	return nil, ErrNotImplemented
}

func (p *Pool) QueryRow(ctx context.Context, sql string, args ...any) *Row {
	return &Row{err: ErrNotImplemented}
}

func (p *Pool) Begin(ctx context.Context) (*Tx, error) {
	return nil, ErrNotImplemented
}

// Tx is one transaction on one connection, returned to the pool by Commit or
// Rollback; a Rollback after Commit is a no-op, so it may always be deferred.
type Tx struct {
	pool *Pool
}

func (t *Tx) Exec(ctx context.Context, sql string, args ...any) (Result, error) {
	return Result{}, ErrNotImplemented
}

func (t *Tx) Query(ctx context.Context, sql string, args ...any) (*Rows, error) {
	return nil, ErrNotImplemented
}

func (t *Tx) QueryRow(ctx context.Context, sql string, args ...any) *Row {
	return &Row{err: ErrNotImplemented}
}

func (t *Tx) Commit(ctx context.Context) error {
	return ErrNotImplemented
}

func (t *Tx) Rollback(ctx context.Context) error {
	return ErrNotImplemented
}

// Result is what a statement reports: the rows it touched.
type Result struct {
	RowsAffected int64
}

// Rows is one result set in the text format, read forward once.
type Rows struct {
	err error
}

func (r *Rows) Next() bool {
	return false
}

// Scan converts the current row's text columns into dest: *string, *[]byte
// (bytea in hex), *bool, *int, *int64, *uint32, *uint8, *time.Time and
// **time.Time, where a NULL sets a pointer to nil and fails anything else.
func (r *Rows) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	return ErrNotImplemented
}

func (r *Rows) Err() error {
	return r.err
}

func (r *Rows) Close() error {
	return nil
}

// Row is the first row of a result, or ErrNoRows when there is none.
type Row struct {
	err error
}

func (r *Row) Scan(dest ...any) error {
	return r.err
}

// Error is the server's ErrorResponse: Code is the SQLSTATE and Constraint
// the name a unique or check violation carries.
type Error struct {
	Severity   string
	Code       string
	Message    string
	Detail     string
	Constraint string
}

func (e *Error) Error() string {
	return "pg: " + e.Severity + " " + e.Code + ": " + e.Message
}

// IsUniqueViolation reports SQLSTATE 23505: a name or a token hash already held.
func IsUniqueViolation(err error) bool {
	var pgErr *Error
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
