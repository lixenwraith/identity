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
	"sync"
	"time"
)

const (
	// DefaultMaxConns is the pool the budget counts: ten connections.
	DefaultMaxConns       = 10
	DefaultConnectTimeout = 5 * time.Second
	defaultPort           = "5432"
)

var (
	ErrNoRows = errors.New("pg: no rows")
	ErrClosed = errors.New("pg: pool is closed")
	ErrTxDone = errors.New("pg: the transaction is finished")
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
	case c.ConnectTimeout <= 0:
		return errors.New("pg: a connect timeout is required")
	}
	return nil
}

// Pool hands out connections to one server, at most MaxConns at once, and
// retries nothing: a statement that failed is the caller's to repeat. A slot
// is held while a connection is in use; an idle connection waits for the next
// caller, and one that failed on the wire is dropped.
type Pool struct {
	cfg    Config
	slots  chan struct{}
	idle   chan *conn
	mu     sync.Mutex
	closed bool
}

// Open checks cfg and connects once, so a wrong password or an unverifiable
// certificate is refused at start and not on the first request.
func Open(ctx context.Context, cfg Config) (*Pool, error) {
	if err := cfg.check(); err != nil {
		return nil, err
	}
	c, err := dial(ctx, cfg)
	if err != nil {
		return nil, err
	}
	p := &Pool{cfg: cfg, slots: make(chan struct{}, cfg.MaxConns), idle: make(chan *conn, cfg.MaxConns)}
	p.idle <- c
	return p, nil
}

func (p *Pool) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	for {
		select {
		case c := <-p.idle:
			c.close()
		default:
			return nil
		}
	}
}

func (p *Pool) acquire(ctx context.Context) (*conn, error) {
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		return nil, ErrClosed
	}
	select {
	case p.slots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case c := <-p.idle:
		return c, nil
	default:
	}
	c, err := dial(ctx, p.cfg)
	if err != nil {
		<-p.slots
		return nil, err
	}
	return c, nil
}

// release returns a connection that is whole and idle; one that broke, or
// was left inside a transaction, is closed instead of being handed on.
func (p *Pool) release(c *conn) {
	p.mu.Lock()
	keep := !p.closed && !c.broken && c.status == 'I'
	if keep {
		p.idle <- c
	}
	p.mu.Unlock()
	if !keep {
		c.close()
	}
	<-p.slots
}

// Exec runs one statement. Without arguments it goes as one simple query, so
// it may hold several statements, as a migration does; with arguments it is
// prepared and bound unnamed, so no value is ever spliced into SQL text.
func (p *Pool) Exec(ctx context.Context, sql string, args ...any) (Result, error) {
	c, err := p.acquire(ctx)
	if err != nil {
		return Result{}, err
	}
	defer p.release(c)
	return exec(ctx, c, sql, args)
}

// Query reads the whole result before it returns, so the connection is back
// in the pool while the caller scans and a slow caller holds no slot.
func (p *Pool) Query(ctx context.Context, sql string, args ...any) (*Rows, error) {
	c, err := p.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer p.release(c)
	return query(ctx, c, sql, args)
}

func (p *Pool) QueryRow(ctx context.Context, sql string, args ...any) *Row {
	return row(p.Query(ctx, sql, args...))
}

func (p *Pool) Begin(ctx context.Context) (*Tx, error) {
	c, err := p.acquire(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := c.query(ctx, "BEGIN", nil); err != nil {
		p.release(c)
		return nil, err
	}
	return &Tx{pool: p, conn: c}, nil
}

func exec(ctx context.Context, c *conn, sql string, args []any) (Result, error) {
	res, err := c.query(ctx, sql, args)
	if err != nil {
		return Result{}, err
	}
	return Result{RowsAffected: rowsAffected(res.tag)}, nil
}

func query(ctx context.Context, c *conn, sql string, args []any) (*Rows, error) {
	res, err := c.query(ctx, sql, args)
	if err != nil {
		return nil, err
	}
	return &Rows{rows: res.rows, at: -1}, nil
}

func row(rows *Rows, err error) *Row {
	if err != nil {
		return &Row{err: err}
	}
	if !rows.Next() {
		return &Row{err: ErrNoRows}
	}
	return &Row{rows: rows}
}

// Tx is one transaction on one connection, returned to the pool by Commit or
// Rollback; a Rollback after Commit is a no-op, so it may always be deferred.
type Tx struct {
	pool *Pool
	conn *conn
}

func (t *Tx) Exec(ctx context.Context, sql string, args ...any) (Result, error) {
	if t.conn == nil {
		return Result{}, ErrTxDone
	}
	return exec(ctx, t.conn, sql, args)
}

func (t *Tx) Query(ctx context.Context, sql string, args ...any) (*Rows, error) {
	if t.conn == nil {
		return nil, ErrTxDone
	}
	return query(ctx, t.conn, sql, args)
}

func (t *Tx) QueryRow(ctx context.Context, sql string, args ...any) *Row {
	return row(t.Query(ctx, sql, args...))
}

// Commit reports a transaction the server rolled back instead, which it does
// for a COMMIT after a failed statement, as an error and not as success.
func (t *Tx) Commit(ctx context.Context) error {
	if t.conn == nil {
		return ErrTxDone
	}
	res, err := t.conn.query(ctx, "COMMIT", nil)
	t.pool.release(t.conn)
	t.conn = nil
	if err == nil && res.tag != "COMMIT" {
		return errors.New("pg: the transaction was rolled back")
	}
	return err
}

func (t *Tx) Rollback(ctx context.Context) error {
	if t.conn == nil {
		return nil
	}
	var err error
	if !t.conn.broken {
		_, err = t.conn.query(ctx, "ROLLBACK", nil)
	}
	t.pool.release(t.conn)
	t.conn = nil
	return err
}

// Result is what a statement reports: the rows it touched.
type Result struct {
	RowsAffected int64
}

// Rows is one result set in the text format, read forward once.
type Rows struct {
	rows [][][]byte
	at   int
}

func (r *Rows) Next() bool {
	if r.at+1 >= len(r.rows) {
		return false
	}
	r.at++
	return true
}

// Scan converts the current row's text columns into dest: *string, *[]byte
// (bytea in hex), *bool, *int, *int32, *int64, *uint32, *uint8, *time.Time,
// and **time.Time or **string, where a NULL sets the pointer to nil and fails
// anything else.
func (r *Rows) Scan(dest ...any) error {
	if r.at < 0 || r.at >= len(r.rows) {
		return errors.New("pg: Scan without a current row")
	}
	row := r.rows[r.at]
	if len(row) != len(dest) {
		return fmt.Errorf("pg: %d columns scanned into %d destinations", len(row), len(dest))
	}
	for i, column := range row {
		if err := scanText(column, dest[i]); err != nil {
			return fmt.Errorf("%w (column %d)", err, i+1)
		}
	}
	return nil
}

func (r *Rows) Err() error {
	return nil
}

func (r *Rows) Close() error {
	r.rows = nil
	return nil
}

// Row is the first row of a result, or ErrNoRows when there is none.
type Row struct {
	rows *Rows
	err  error
}

func (r *Row) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	return r.rows.Scan(dest...)
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
