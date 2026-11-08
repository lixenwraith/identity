// Package store keeps accounts, their SCRAM verifiers and their sign-ins in
// PostgreSQL through pg, one statement a method, in the schema the embedded
// migrations describe. It holds no password and no token: the verifier a
// device derived, and the SHA-256 of each token the device keeps.
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/lixenwraith/identity/internal/pg"

	"github.com/lixenwraith/auth"
)

const (
	// SignInLifetime slides from each use; a device unseen for this long signs in again.
	SignInLifetime = 30 * 24 * time.Hour
	// TokenBytes is a sign-in token's entropy; the store keeps its SHA-256 alone.
	TokenBytes = 32
	MaxDevice  = 64

	// Two advisory locks, scoped to the database, serialize the operations that
	// read before they write: the schema's version and the account count.
	migrateLockKey int64 = 0x6964656e74697479
	createLockKey  int64 = 0x6964656e74697461
)

var (
	ErrNotFound     = errors.New("store: not found")
	ErrNameTaken    = errors.New("store: the name is taken")
	ErrInvalidName  = errors.New("store: a name is 1 to 32 of a-z, 0-9, _ and -, starting with a letter")
	ErrAccountsFull = errors.New("store: no room for another account")
	ErrSchema       = errors.New("store: the database schema is not the one this binary expects")
)

// namePattern is the schema's accounts_name_check: a roster-safe name in one
// spelling, so what the coordinator copies onto a roster entry needs no escaping.
var namePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

// NormalizeName lowercases a name and holds it to the pattern, so two spellings
// are one account and the store's unique constraint is case-insensitive.
func NormalizeName(name string) (string, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if !namePattern.MatchString(name) {
		return "", ErrInvalidName
	}
	return name, nil
}

type Account struct {
	ID         string
	Name       string
	CreatedAt  time.Time
	DisabledAt *time.Time
}

// Verifier is one account's SCRAM credential as stored: the auth package's
// Credential with the account in place of the password it never saw.
type Verifier struct {
	AccountID    string
	Name         string
	Salt         []byte
	ArgonTime    uint32
	ArgonMemory  uint32
	ArgonThreads uint8
	StoredKey    []byte
	ServerKey    []byte
}

// VerifierOf keeps what a credential proves and drops its username, which the
// account row holds once.
func VerifierOf(accountID string, c *auth.Credential) Verifier {
	return Verifier{
		AccountID: accountID, Name: c.Username, Salt: c.Salt,
		ArgonTime: c.ArgonTime, ArgonMemory: c.ArgonMemory, ArgonThreads: c.ArgonThreads,
		StoredKey: c.StoredKey, ServerKey: c.ServerKey,
	}
}

func (v Verifier) Credential() *auth.Credential {
	return &auth.Credential{
		Username: v.Name, Salt: v.Salt,
		ArgonTime: v.ArgonTime, ArgonMemory: v.ArgonMemory, ArgonThreads: v.ArgonThreads,
		StoredKey: v.StoredKey, ServerKey: v.ServerKey,
	}
}

type SignIn struct {
	ID         string
	AccountID  string
	TokenHash  []byte
	Device     string
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
}

// HashToken is what a sign-in row keeps of a token, so a copy of the table
// signs nobody in; a lookup hashes the presented token the same way.
func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// NewID is a random UUID (version 4) in its canonical text form.
func NewID() string {
	var b [16]byte
	rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	var out [36]byte
	hex.Encode(out[:8], b[:4])
	out[8] = '-'
	hex.Encode(out[9:13], b[4:6])
	out[13] = '-'
	hex.Encode(out[14:18], b[6:8])
	out[18] = '-'
	hex.Encode(out[19:23], b[8:10])
	out[23] = '-'
	hex.Encode(out[24:], b[10:])
	return string(out[:])
}

// Store is the service's view of its database, safe for concurrent use.
type Store struct {
	db *pg.Pool
}

func New(db *pg.Pool) *Store {
	return &Store{db: db}
}

type querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pg.Result, error)
	QueryRow(ctx context.Context, sql string, args ...any) *pg.Row
}

const accountColumns = `account_id, name, created_at, disabled_at`

// CreateAccount makes an account with its verifier under the deployment's cap;
// 0 is no cap. The count and the insert sit under one advisory lock, so two
// registrations cannot both pass the last free place.
func (s *Store) CreateAccount(ctx context.Context, name string, v Verifier, maxAccounts int) (Account, error) {
	name, err := NormalizeName(name)
	if err != nil {
		return Account{}, err
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return Account{}, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, createLockKey); err != nil {
		return Account{}, err
	}
	var taken bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM accounts WHERE name = $1)`, name).Scan(&taken); err != nil {
		return Account{}, err
	}
	if taken {
		return Account{}, ErrNameTaken
	}
	if maxAccounts > 0 {
		var total int64
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM accounts`).Scan(&total); err != nil {
			return Account{}, err
		}
		if total >= int64(maxAccounts) {
			return Account{}, ErrAccountsFull
		}
	}
	a := Account{ID: NewID(), Name: name, CreatedAt: time.Now().UTC()}
	if _, err := tx.Exec(ctx, `INSERT INTO accounts (account_id, name, created_at) VALUES ($1, $2, $3)`,
		a.ID, a.Name, a.CreatedAt); err != nil {
		if pg.IsUniqueViolation(err) {
			return Account{}, ErrNameTaken
		}
		return Account{}, err
	}
	v.AccountID = a.ID
	if err := putVerifier(ctx, tx, v); err != nil {
		return Account{}, err
	}
	return a, tx.Commit(ctx)
}

func putVerifier(ctx context.Context, q querier, v Verifier) error {
	_, err := q.Exec(ctx, `INSERT INTO verifiers
			(account_id, salt, argon_time, argon_memory, argon_threads, stored_key, server_key)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (account_id) DO UPDATE SET
			salt = excluded.salt, argon_time = excluded.argon_time, argon_memory = excluded.argon_memory,
			argon_threads = excluded.argon_threads, stored_key = excluded.stored_key,
			server_key = excluded.server_key, updated_at = now()`,
		v.AccountID, v.Salt, int64(v.ArgonTime), int64(v.ArgonMemory), int64(v.ArgonThreads), v.StoredKey, v.ServerKey)
	return err
}

// SetVerifier replaces an account's credential: the operator's reset, the one
// place a password is derived on the server.
func (s *Store) SetVerifier(ctx context.Context, v Verifier) error {
	return putVerifier(ctx, s.db, v)
}

// Verifiers lists every enabled account's credential, what the SCRAM server
// is loaded with at start; a disabled account is unknown to it, so its
// sign-in fails as a wrong password does.
func (s *Store) Verifiers(ctx context.Context) ([]Verifier, error) {
	rows, err := s.db.Query(ctx, `SELECT a.name, v.account_id, v.salt, v.argon_time, v.argon_memory,
			v.argon_threads, v.stored_key, v.server_key
		FROM verifiers v JOIN accounts a USING (account_id)
		WHERE a.disabled_at IS NULL ORDER BY a.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []Verifier
	for rows.Next() {
		var v Verifier
		if err := rows.Scan(&v.Name, &v.AccountID, &v.Salt, &v.ArgonTime, &v.ArgonMemory,
			&v.ArgonThreads, &v.StoredKey, &v.ServerKey); err != nil {
			return nil, err
		}
		list = append(list, v)
	}
	return list, rows.Err()
}

func (s *Store) AccountByID(ctx context.Context, id string) (Account, error) {
	return s.account(ctx, `account_id = $1`, id)
}

func (s *Store) AccountByName(ctx context.Context, name string) (Account, error) {
	name, err := NormalizeName(name)
	if err != nil {
		return Account{}, ErrNotFound
	}
	return s.account(ctx, `name = $1`, name)
}

func (s *Store) account(ctx context.Context, where string, arg any) (Account, error) {
	var a Account
	err := s.db.QueryRow(ctx, `SELECT `+accountColumns+` FROM accounts WHERE `+where, arg).
		Scan(&a.ID, &a.Name, &a.CreatedAt, &a.DisabledAt)
	if errors.Is(err, pg.ErrNoRows) {
		return Account{}, ErrNotFound
	}
	return a, err
}

// Accounts lists every account, oldest first: the operator's view.
func (s *Store) Accounts(ctx context.Context) ([]Account, error) {
	rows, err := s.db.Query(ctx, `SELECT `+accountColumns+` FROM accounts ORDER BY created_at, account_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []Account
	for rows.Next() {
		var a Account
		if err := rows.Scan(&a.ID, &a.Name, &a.CreatedAt, &a.DisabledAt); err != nil {
			return nil, err
		}
		list = append(list, a)
	}
	return list, rows.Err()
}

// SetDisabled closes or reopens an account. Disabling leaves its sign-ins in
// place and useless, since a lookup joins an enabled account alone.
func (s *Store) SetDisabled(ctx context.Context, id string, disabled bool) error {
	var at *time.Time
	if disabled {
		now := time.Now().UTC()
		at = &now
	}
	return s.one(ctx, `UPDATE accounts SET disabled_at = $2 WHERE account_id = $1`, id, at)
}

func (s *Store) DeleteAccount(ctx context.Context, id string) error {
	return s.one(ctx, `DELETE FROM accounts WHERE account_id = $1`, id)
}

func (s *Store) CreateSignIn(ctx context.Context, in SignIn) error {
	_, err := s.db.Exec(ctx, `INSERT INTO sign_ins
			(sign_in_id, account_id, token_hash, device, created_at, last_seen_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		in.ID, in.AccountID, in.TokenHash, in.Device, in.CreatedAt, in.LastSeenAt, in.ExpiresAt)
	return err
}

// SignInByToken answers the router's question and every signed-in request:
// the live sign-in a token names and its enabled account, or ErrNotFound for
// an unknown, expired or disabled one alike.
func (s *Store) SignInByToken(ctx context.Context, tokenHash []byte) (SignIn, Account, error) {
	var in SignIn
	var a Account
	err := s.db.QueryRow(ctx, `SELECT s.sign_in_id, s.account_id, s.device, s.created_at, s.last_seen_at, s.expires_at,
			a.name, a.created_at
		FROM sign_ins s JOIN accounts a USING (account_id)
		WHERE s.token_hash = $1 AND s.expires_at > now() AND a.disabled_at IS NULL`, tokenHash).
		Scan(&in.ID, &in.AccountID, &in.Device, &in.CreatedAt, &in.LastSeenAt, &in.ExpiresAt, &a.Name, &a.CreatedAt)
	if errors.Is(err, pg.ErrNoRows) {
		return SignIn{}, Account{}, ErrNotFound
	}
	in.TokenHash = tokenHash
	a.ID = in.AccountID
	return in, a, err
}

// RenewSignIn slides a sign-in past half its life: last seen now, expiring a
// lifetime from now.
func (s *Store) RenewSignIn(ctx context.Context, id string, now time.Time) error {
	return s.one(ctx, `UPDATE sign_ins SET last_seen_at = $2, expires_at = $3 WHERE sign_in_id = $1`,
		id, now, now.Add(SignInLifetime))
}

func (s *Store) SignIns(ctx context.Context, accountID string) ([]SignIn, error) {
	rows, err := s.db.Query(ctx, `SELECT sign_in_id, account_id, token_hash, device, created_at, last_seen_at, expires_at
		FROM sign_ins WHERE account_id = $1 AND expires_at > now() ORDER BY created_at, sign_in_id`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []SignIn
	for rows.Next() {
		var in SignIn
		if err := rows.Scan(&in.ID, &in.AccountID, &in.TokenHash, &in.Device, &in.CreatedAt, &in.LastSeenAt, &in.ExpiresAt); err != nil {
			return nil, err
		}
		list = append(list, in)
	}
	return list, rows.Err()
}

// DeleteSignIn revokes one of an account's sign-ins; the account is part of
// the key, so a signed-in device revokes its own account's alone.
func (s *Store) DeleteSignIn(ctx context.Context, accountID, id string) error {
	return s.one(ctx, `DELETE FROM sign_ins WHERE account_id = $1 AND sign_in_id = $2`, accountID, id)
}

// DeleteSignInByToken is a logout: the presented token's sign-in goes.
func (s *Store) DeleteSignInByToken(ctx context.Context, tokenHash []byte) error {
	return s.one(ctx, `DELETE FROM sign_ins WHERE token_hash = $1`, tokenHash)
}

// DeleteSignIns revokes every sign-in of an account, as a reset does.
func (s *Store) DeleteSignIns(ctx context.Context, accountID string) (int64, error) {
	res, err := s.db.Exec(ctx, `DELETE FROM sign_ins WHERE account_id = $1`, accountID)
	return res.RowsAffected, err
}

func (s *Store) DeleteExpiredSignIns(ctx context.Context) (int64, error) {
	res, err := s.db.Exec(ctx, `DELETE FROM sign_ins WHERE expires_at <= now()`)
	return res.RowsAffected, err
}

// one runs a statement that must touch one row, and reports none as ErrNotFound.
func (s *Store) one(ctx context.Context, sql string, args ...any) error {
	res, err := s.db.Exec(ctx, sql, args...)
	if err != nil {
		return err
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	if res.RowsAffected != 1 {
		return fmt.Errorf("store: statement touched %d rows", res.RowsAffected)
	}
	return nil
}
