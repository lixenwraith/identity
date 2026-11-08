package pg_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lixenwraith/identity/internal/dbtest"
	"github.com/lixenwraith/identity/internal/pg"
)

func TestAURLNamesTheServerAndNeverThePassword(t *testing.T) {
	cfg, err := pg.ParseURL("postgres://identity@db.example.test/identity?sslmode=verify-full")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Host != "db.example.test" || cfg.Port != "5432" || cfg.Database != "identity" || cfg.User != "identity" {
		t.Fatalf("parsed %+v", cfg)
	}
	if cfg.MaxConns != pg.DefaultMaxConns || cfg.ConnectTimeout != pg.DefaultConnectTimeout {
		t.Fatalf("defaults not applied: %+v", cfg)
	}
	if cfg, err := pg.ParseURL("postgresql://identity@[fd00::10]:5433/identity"); err != nil || cfg.Host != "fd00::10" || cfg.Port != "5433" {
		t.Fatalf("IPv6 host: %+v, %v", cfg, err)
	}
	for _, raw := range []string{
		"postgres://identity:secret@db.example.test/identity",
		"postgres://db.example.test/identity",
		"postgres://identity@/identity",
		"postgres://identity@db.example.test",
		"postgres://identity@db.example.test/",
		"postgres://identity@db.example.test/identity?sslmode=require",
		"postgres://identity@db.example.test/identity?sslmode=disable",
		"postgres://identity@db.example.test/identity?sslrootcert=/x",
		"postgres://identity@db.example.test/identity#f",
		"mysql://identity@db.example.test/identity",
		"://",
	} {
		if _, err := pg.ParseURL(raw); err == nil {
			t.Errorf("%q was accepted", raw)
		}
	}
}

func TestOpenChecksTheConfigBeforeDialling(t *testing.T) {
	cfg, _ := pg.ParseURL("postgres://identity@db.example.test/identity")
	if _, err := pg.Open(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "password") {
		t.Fatalf("a config without a password was not refused by name: %v", err)
	}
	cfg.Password = "x"
	if _, err := pg.Open(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "TLS") {
		t.Fatalf("a config without TLS was not refused by name: %v", err)
	}
}

func TestTLSTrustsTheGivenCertificateAlone(t *testing.T) {
	if _, err := pg.TLSConfig(nil, ""); err == nil {
		t.Fatal("an empty server name was accepted")
	}
	cfg, err := pg.TLSConfig(nil, "db.example.test")
	if err != nil || cfg.RootCAs != nil || cfg.ServerName != "db.example.test" {
		t.Fatalf("system roots: %+v, %v", cfg, err)
	}
	if _, err := pg.TLSConfig([]byte("not a certificate"), "db.example.test"); err == nil {
		t.Fatal("a CA file without a certificate was accepted")
	}
	cfg, err = pg.TLSConfig(selfSigned(t), "db.example.test")
	if err != nil || cfg.RootCAs == nil {
		t.Fatalf("self-signed certificate: %+v, %v", cfg, err)
	}
}

func selfSigned(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "db.example.test"},
		DNSNames:     []string{"db.example.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// testConfig is the test database's pg.Config with the password and the CA the
// environment names, so a test can vary one setting against the real server.
func testConfig(t *testing.T) pg.Config {
	t.Helper()
	cfg, err := pg.ParseURL(os.Getenv(dbtest.URLVar))
	if err != nil {
		t.Fatal(err)
	}
	password, err := os.ReadFile(os.Getenv(dbtest.PasswordFileVar))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Password = strings.TrimRight(string(password), "\r\n")
	var ca []byte
	if path := os.Getenv(dbtest.CAVar); path != "" {
		if ca, err = os.ReadFile(path); err != nil {
			t.Fatal(err)
		}
	}
	if cfg.TLS, err = pg.TLSConfig(ca, cfg.Host); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestOpenProvesTheRoleOverTLSAndRefusesAnythingLess(t *testing.T) {
	dbtest.Pool(t).Close()
	ctx := context.Background()
	cfg := testConfig(t)
	cfg.Password += "-wrong"
	var pgErr *pg.Error
	if _, err := pg.Open(ctx, cfg); !errors.As(err, &pgErr) || pgErr.Code != "28P01" {
		t.Fatalf("a wrong password: %v", err)
	}
	cfg = testConfig(t)
	cfg.TLS.ServerName = "other.example.test"
	if _, err := pg.Open(ctx, cfg); err == nil || errors.As(err, &pgErr) {
		t.Fatalf("a certificate for another name was accepted: %v", err)
	}
	cfg = testConfig(t)
	cfg.TLS.RootCAs = nil
	cfg.TLS.InsecureSkipVerify = false
	if _, err := pg.Open(ctx, cfg); err == nil || errors.As(err, &pgErr) {
		t.Fatalf("a certificate the roots do not sign was accepted: %v", err)
	}
}

// Each type the store reads or writes goes to the server and back unchanged.
func TestEveryTypeRoundTripsAsText(t *testing.T) {
	pool := dbtest.Pool(t)
	ctx := context.Background()
	when := time.Date(2026, 3, 4, 5, 6, 7, 891011000, time.FixedZone("x", 3600))
	blob := []byte{0, 1, 2, 0xfe, 0xff}
	var (
		text   string
		bin    []byte
		small  uint8
		medium uint32
		plain  int
		wide   int64
		narrow int32
		yes    bool
		at     time.Time
		id     string
		none   *time.Time
		some   *time.Time
		label  *string
	)
	err := pool.QueryRow(ctx, `SELECT $1::text, $2::bytea, $3::int2, $4::int8, $5::int8, $6::int8, $7::int4, $8::bool,
			$9::timestamptz, $10::uuid, $11::timestamptz, $12::timestamptz, $13::text`,
		"héllo, world", blob, uint8(200), uint32(4000000000), 42, int64(-1)<<40, int32(-7), true,
		when, "0d4a2c1e-5b3f-4c8d-9e1a-2b3c4d5e6f70", nil, &when, (*string)(nil)).
		Scan(&text, &bin, &small, &medium, &plain, &wide, &narrow, &yes, &at, &id, &none, &some, &label)
	if err != nil {
		t.Fatal(err)
	}
	if text != "héllo, world" || !bytes.Equal(bin, blob) || small != 200 || medium != 4000000000 || plain != 42 ||
		wide != int64(-1)<<40 || narrow != -7 || !yes || id != "0d4a2c1e-5b3f-4c8d-9e1a-2b3c4d5e6f70" {
		t.Fatalf("scanned %q %x %d %d %d %d %d %v %q", text, bin, small, medium, plain, wide, narrow, yes, id)
	}
	if !at.Equal(when) || at.Location() != time.UTC {
		t.Fatalf("time %v, want %v in UTC", at, when)
	}
	if none != nil || some == nil || !some.Equal(when) || label != nil {
		t.Fatalf("NULL handling: %v %v %v", none, some, label)
	}
	if err := pool.QueryRow(ctx, `SELECT NULL::text`).Scan(&text); err == nil {
		t.Fatal("a NULL was scanned into a string")
	}
	if err := pool.QueryRow(ctx, `SELECT 1 WHERE false`).Scan(&plain); !errors.Is(err, pg.ErrNoRows) {
		t.Fatalf("an empty result: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT 1, 2`).Scan(&plain); err == nil {
		t.Fatal("two columns were scanned into one destination")
	}
	if _, err := pool.Exec(ctx, `SELECT $1::text`, 3.5); err == nil {
		t.Fatal("a float was encoded")
	}
}

// A simple query carries several statements, as a migration does; a bound
// one is a single statement whose error names its SQLSTATE and constraint.
func TestStatementsRunPlainOrBoundAndErrorsAreTheServers(t *testing.T) {
	pool := dbtest.Pool(t)
	ctx := context.Background()
	table := "pg_test_" + strings.ToLower(rand.Text()[:8])
	defer pool.Exec(ctx, `DROP TABLE IF EXISTS `+table)
	res, err := pool.Exec(ctx, `CREATE TABLE `+table+` (n int PRIMARY KEY, label text NOT NULL,
			CONSTRAINT `+table+`_label_key UNIQUE (label));
		INSERT INTO `+table+` VALUES (1, 'one'), (2, 'two');
		INSERT INTO `+table+` VALUES (3, 'three')`)
	if err != nil || res.RowsAffected != 1 {
		t.Fatalf("simple query: %+v, %v", res, err)
	}
	res, err = pool.Exec(ctx, `UPDATE `+table+` SET label = label || $1 WHERE n > $2`, "!", 1)
	if err != nil || res.RowsAffected != 2 {
		t.Fatalf("bound update: %+v, %v", res, err)
	}
	rows, err := pool.Query(ctx, `SELECT n, label FROM `+table+` ORDER BY n`)
	if err != nil {
		t.Fatal(err)
	}
	var seen []string
	for rows.Next() {
		var n int
		var label string
		if err := rows.Scan(&n, &label); err != nil {
			t.Fatal(err)
		}
		seen = append(seen, label)
	}
	if strings.Join(seen, " ") != "one two! three!" || rows.Err() != nil {
		t.Fatalf("read %q", seen)
	}
	_, err = pool.Exec(ctx, `INSERT INTO `+table+` VALUES ($1, $2)`, 4, "one")
	var pgErr *pg.Error
	if !pg.IsUniqueViolation(err) || !errors.As(err, &pgErr) || pgErr.Constraint != table+"_label_key" || pgErr.Severity != "ERROR" {
		t.Fatalf("unique violation: %v", err)
	}
	if _, err := pool.Exec(ctx, `SELECT * FROM no_such_table`); !errors.As(err, &pgErr) || pgErr.Code != "42P01" {
		t.Fatalf("an unknown table: %v", err)
	}
	if _, err := pool.Exec(ctx, `SELECT 1; SELECT * FROM no_such_table; SELECT 2`); !errors.As(err, &pgErr) || pgErr.Code != "42P01" {
		t.Fatalf("an error inside a simple query: %v", err)
	}
	if res, err := pool.Exec(ctx, `SELECT $1::int`, 1); err != nil || res.RowsAffected != 1 {
		t.Fatalf("the connection after an error: %+v, %v", res, err)
	}
}

func TestATransactionCommitsWholeOrNotAtAll(t *testing.T) {
	pool := dbtest.Pool(t)
	ctx := context.Background()
	table := "pg_test_" + strings.ToLower(rand.Text()[:8])
	if _, err := pool.Exec(ctx, `CREATE TABLE `+table+` (n int PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	defer pool.Exec(ctx, `DROP TABLE `+table)
	count := func() int {
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM `+table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO `+table+` VALUES ($1)`, 1); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(ctx); err != nil || count() != 0 {
		t.Fatalf("after rollback: %d rows, %v", count(), err)
	}
	tx, err = pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO `+table+` VALUES ($1)`, 1); err != nil {
		t.Fatal(err)
	}
	var inside int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM `+table).Scan(&inside); err != nil || inside != 1 {
		t.Fatalf("inside the transaction: %d, %v", inside, err)
	}
	if err := tx.Commit(ctx); err != nil || count() != 1 {
		t.Fatalf("after commit: %d rows, %v", count(), err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatalf("a rollback after commit is a no-op: %v", err)
	}
	if _, err := tx.Exec(ctx, `SELECT 1`); !errors.Is(err, pg.ErrTxDone) {
		t.Fatalf("a finished transaction: %v", err)
	}
	// A failed statement aborts the transaction, so its COMMIT is a rollback.
	tx, err = pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO `+table+` VALUES ($1)`, 1); !pg.IsUniqueViolation(err) {
		t.Fatalf("duplicate inside a transaction: %v", err)
	}
	if err := tx.Commit(ctx); err == nil || count() != 1 {
		t.Fatalf("a commit after a failure: %v", err)
	}
}

// A cancelled statement closes its connection; the pool dials another, and
// no more than MaxConns are ever open.
func TestACancelledStatementCostsOnlyItsConnection(t *testing.T) {
	dbtest.Pool(t).Close()
	cfg := testConfig(t)
	cfg.MaxConns = 2
	ctx := context.Background()
	pool, err := pg.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	short, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := pool.Exec(short, `SELECT pg_sleep(5)`); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a timed-out statement: %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("the statement ran to its end")
	}
	var one int
	if err := pool.QueryRow(ctx, `SELECT 1`).Scan(&one); err != nil || one != 1 {
		t.Fatalf("the pool after a broken connection: %v", err)
	}
	first, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	second, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	waiting, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	if _, err := pool.Begin(waiting); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a third connection was opened: %v", err)
	}
	if err := first.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := second.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT 1`).Scan(&one); err != nil {
		t.Fatal(err)
	}
	if err := pool.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `SELECT 1`); !errors.Is(err, pg.ErrClosed) {
		t.Fatalf("a closed pool: %v", err)
	}
}
