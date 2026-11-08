package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
)

// FileVersion is the file format's version, recorded in the file and refused
// when newer than the binary knows; a change to the format bumps it.
const FileVersion = 1

var (
	ErrLocked   = errors.New("store: the file is held by another process")
	ErrReadOnly = errors.New("store: the file was opened read-only")
)

// File keeps the accounts, their verifiers and their sign-ins in one JSON file,
// 0600, read at open and rewritten whole on every change through a rename, so
// the file on disk is always complete. For a deployment too small for a
// database, and for the tests. A writer holds a lock beside the file for as
// long as it is open, so a service and an operator's command never write past
// each other; the command runs while the service is stopped, and the service
// loads the file at start.
type File struct {
	path     string
	readOnly bool
	lock     *os.File
	mu       syncMutex
	data     fileData
}

type fileData struct {
	Version  int           `json:"version"`
	Accounts []fileAccount `json:"accounts"`
	SignIns  []fileSignIn  `json:"sign_ins"`
}

type fileAccount struct {
	ID         string        `json:"id"`
	Name       string        `json:"name"`
	CreatedAt  time.Time     `json:"created_at"`
	DisabledAt *time.Time    `json:"disabled_at,omitempty"`
	Verifier   *fileVerifier `json:"verifier,omitempty"`
}

type fileVerifier struct {
	Salt         []byte `json:"salt"`
	ArgonTime    uint32 `json:"argon_time"`
	ArgonMemory  uint32 `json:"argon_memory"`
	ArgonThreads uint8  `json:"argon_threads"`
	StoredKey    []byte `json:"stored_key"`
	ServerKey    []byte `json:"server_key"`
}

type fileSignIn struct {
	ID         string    `json:"id"`
	AccountID  string    `json:"account_id"`
	TokenHash  []byte    `json:"token_hash"`
	Device     string    `json:"device"`
	CreatedAt  time.Time `json:"created_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// OpenFile opens the store at path, making an empty one when none exists; the
// directory must. Read-only takes no lock and refuses every change, for a
// command that only lists while the service holds the file.
func OpenFile(path string, readOnly bool) (*File, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("store: %q is not an absolute path", path)
	}
	f := &File{path: path, readOnly: readOnly}
	if !readOnly {
		lock, err := os.OpenFile(path+".lock", os.O_RDWR|os.O_CREATE, 0o600)
		if err != nil {
			return nil, fmt.Errorf("store: %w", err)
		}
		if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			_ = lock.Close()
			if errors.Is(err, syscall.EWOULDBLOCK) {
				return nil, fmt.Errorf("%w: %s", ErrLocked, path)
			}
			return nil, fmt.Errorf("store: lock %s: %w", path, err)
		}
		f.lock = lock
	}
	if err := f.load(); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

func (f *File) load() error {
	raw, err := os.ReadFile(f.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		f.data = fileData{Version: FileVersion}
		if f.readOnly {
			return nil
		}
		return f.write(f.data)
	case err != nil:
		return fmt.Errorf("store: %w", err)
	}
	var data fileData
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&data); err != nil {
		return fmt.Errorf("store: %s is not a store file: %w", f.path, err)
	}
	if data.Version > FileVersion {
		return fmt.Errorf("%w: file at version %d, binary at %d", ErrSchema, data.Version, FileVersion)
	}
	f.data = data
	return nil
}

// write lands the whole store through a temporary file and a rename, both
// synced, so a crash leaves the previous file or the new one and never a torn one.
func (f *File) write(data fileData) error {
	raw, err := json.MarshalIndent(data, "", "\t")
	if err != nil {
		return err
	}
	dir := filepath.Dir(f.path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(f.path)+".*")
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	name := tmp.Name()
	fail := func(err error) error {
		_ = tmp.Close()
		_ = os.Remove(name)
		return fmt.Errorf("store: write %s: %w", f.path, err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		return fail(err)
	}
	if _, err := tmp.Write(append(raw, '\n')); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("store: write %s: %w", f.path, err)
	}
	if err := os.Rename(name, f.path); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("store: write %s: %w", f.path, err)
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// Close releases the lock; the file itself needs nothing, every change having landed.
func (f *File) Close() error {
	if f.lock == nil {
		return nil
	}
	err := f.lock.Close()
	f.lock = nil
	return err
}

// Path is where the store lives, for the start-up log line.
func (f *File) Path() string { return f.path }

// update applies one change to a copy and lands it before the copy becomes the
// store, so a failed write leaves memory and disk agreeing on the old state.
func (f *File) update(mutate func(d *fileData) error) error {
	if f.readOnly {
		return ErrReadOnly
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	next := f.data.clone()
	if err := mutate(&next); err != nil {
		return err
	}
	if err := f.write(next); err != nil {
		return err
	}
	f.data = next
	return nil
}

func (d fileData) clone() fileData {
	out := fileData{Version: d.Version, Accounts: make([]fileAccount, len(d.Accounts)), SignIns: slices.Clone(d.SignIns)}
	for i, a := range d.Accounts {
		if a.DisabledAt != nil {
			at := *a.DisabledAt
			a.DisabledAt = &at
		}
		if a.Verifier != nil {
			v := *a.Verifier
			a.Verifier = &v
		}
		out.Accounts[i] = a
	}
	return out
}

func (d *fileData) account(id string) *fileAccount {
	for i := range d.Accounts {
		if d.Accounts[i].ID == id {
			return &d.Accounts[i]
		}
	}
	return nil
}

func (a fileAccount) export() Account {
	return Account{ID: a.ID, Name: a.Name, CreatedAt: a.CreatedAt, DisabledAt: a.DisabledAt}
}

func (in fileSignIn) export() SignIn {
	return SignIn{ID: in.ID, AccountID: in.AccountID, TokenHash: in.TokenHash, Device: in.Device,
		CreatedAt: in.CreatedAt, LastSeenAt: in.LastSeenAt, ExpiresAt: in.ExpiresAt}
}

// Migrate brings the file to the binary's format version; an empty store is
// made at open, so there is nothing to apply until a later format.
func (f *File) Migrate(context.Context) (from, to int, err error) {
	f.mu.Lock()
	from = f.data.Version
	f.mu.Unlock()
	if from == FileVersion {
		return from, FileVersion, nil
	}
	err = f.update(func(d *fileData) error {
		d.Version = FileVersion
		return nil
	})
	return from, FileVersion, err
}

func (f *File) CheckSchema(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.data.Version != FileVersion {
		return fmt.Errorf("%w: file at version %d, binary at %d", ErrSchema, f.data.Version, FileVersion)
	}
	return nil
}

func (f *File) CreateAccount(_ context.Context, name string, v Verifier, maxAccounts int) (Account, error) {
	name, err := NormalizeName(name)
	if err != nil {
		return Account{}, err
	}
	a := fileAccount{ID: NewID(), Name: name, CreatedAt: Now(), Verifier: verifierOf(v)}
	err = f.update(func(d *fileData) error {
		for _, other := range d.Accounts {
			if other.Name == name {
				return ErrNameTaken
			}
		}
		if maxAccounts > 0 && len(d.Accounts) >= maxAccounts {
			return ErrAccountsFull
		}
		d.Accounts = append(d.Accounts, a)
		return nil
	})
	return a.export(), err
}

func verifierOf(v Verifier) *fileVerifier {
	return &fileVerifier{Salt: v.Salt, ArgonTime: v.ArgonTime, ArgonMemory: v.ArgonMemory,
		ArgonThreads: v.ArgonThreads, StoredKey: v.StoredKey, ServerKey: v.ServerKey}
}

func (f *File) SetVerifier(_ context.Context, v Verifier) error {
	return f.update(func(d *fileData) error {
		a := d.account(v.AccountID)
		if a == nil {
			return ErrNotFound
		}
		a.Verifier = verifierOf(v)
		return nil
	})
}

func (f *File) Verifiers(context.Context) ([]Verifier, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var list []Verifier
	for _, a := range f.data.Accounts {
		if a.DisabledAt != nil || a.Verifier == nil {
			continue
		}
		v := a.Verifier
		list = append(list, Verifier{AccountID: a.ID, Name: a.Name, Salt: v.Salt, ArgonTime: v.ArgonTime,
			ArgonMemory: v.ArgonMemory, ArgonThreads: v.ArgonThreads, StoredKey: v.StoredKey, ServerKey: v.ServerKey})
	}
	slices.SortFunc(list, func(a, b Verifier) int { return strings.Compare(a.Name, b.Name) })
	return list, nil
}

func (f *File) AccountByID(_ context.Context, id string) (Account, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if a := f.data.account(id); a != nil {
		return a.export(), nil
	}
	return Account{}, ErrNotFound
}

func (f *File) AccountByName(_ context.Context, name string) (Account, error) {
	name, err := NormalizeName(name)
	if err != nil {
		return Account{}, ErrNotFound
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, a := range f.data.Accounts {
		if a.Name == name {
			return a.export(), nil
		}
	}
	return Account{}, ErrNotFound
}

func (f *File) Accounts(context.Context) ([]Account, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	list := make([]Account, 0, len(f.data.Accounts))
	for _, a := range f.data.Accounts {
		list = append(list, a.export())
	}
	slices.SortFunc(list, func(a, b Account) int {
		if c := a.CreatedAt.Compare(b.CreatedAt); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	return list, nil
}

func (f *File) SetDisabled(_ context.Context, id string, disabled bool) error {
	return f.update(func(d *fileData) error {
		a := d.account(id)
		if a == nil {
			return ErrNotFound
		}
		a.DisabledAt = nil
		if disabled {
			now := Now()
			a.DisabledAt = &now
		}
		return nil
	})
}

// DeleteAccount takes the account's sign-ins with it, as the schema's cascade does.
func (f *File) DeleteAccount(_ context.Context, id string) error {
	return f.update(func(d *fileData) error {
		if d.account(id) == nil {
			return ErrNotFound
		}
		d.Accounts = slices.DeleteFunc(d.Accounts, func(a fileAccount) bool { return a.ID == id })
		d.SignIns = slices.DeleteFunc(d.SignIns, func(in fileSignIn) bool { return in.AccountID == id })
		return nil
	})
}

func (f *File) CreateSignIn(_ context.Context, in SignIn) error {
	return f.update(func(d *fileData) error {
		if d.account(in.AccountID) == nil {
			return fmt.Errorf("store: sign-in for an account that does not exist")
		}
		for _, other := range d.SignIns {
			if other.ID == in.ID || slices.Equal(other.TokenHash, in.TokenHash) {
				return fmt.Errorf("store: a sign-in with that id or token exists")
			}
		}
		d.SignIns = append(d.SignIns, fileSignIn{ID: in.ID, AccountID: in.AccountID, TokenHash: in.TokenHash,
			Device: in.Device, CreatedAt: in.CreatedAt, LastSeenAt: in.LastSeenAt, ExpiresAt: in.ExpiresAt})
		return nil
	})
}

func (f *File) SignInByToken(_ context.Context, tokenHash []byte) (SignIn, Account, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := Now()
	for _, in := range f.data.SignIns {
		if !slices.Equal(in.TokenHash, tokenHash) || !in.ExpiresAt.After(now) {
			continue
		}
		if a := f.data.account(in.AccountID); a != nil && a.DisabledAt == nil {
			return in.export(), a.export(), nil
		}
	}
	return SignIn{}, Account{}, ErrNotFound
}

func (f *File) RenewSignIn(_ context.Context, id string, now time.Time) error {
	return f.update(func(d *fileData) error {
		for i := range d.SignIns {
			if d.SignIns[i].ID == id {
				d.SignIns[i].LastSeenAt = now
				d.SignIns[i].ExpiresAt = now.Add(SignInLifetime)
				return nil
			}
		}
		return ErrNotFound
	})
}

func (f *File) SignIns(_ context.Context, accountID string) ([]SignIn, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := Now()
	var list []SignIn
	for _, in := range f.data.SignIns {
		if in.AccountID == accountID && in.ExpiresAt.After(now) {
			list = append(list, in.export())
		}
	}
	slices.SortFunc(list, func(a, b SignIn) int {
		if c := a.CreatedAt.Compare(b.CreatedAt); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	return list, nil
}

func (f *File) DeleteSignIn(_ context.Context, accountID, id string) error {
	return f.deleteSignIns(func(in fileSignIn) bool { return in.AccountID == accountID && in.ID == id }, true)
}

func (f *File) DeleteSignInByToken(_ context.Context, tokenHash []byte) error {
	return f.deleteSignIns(func(in fileSignIn) bool { return slices.Equal(in.TokenHash, tokenHash) }, true)
}

func (f *File) DeleteSignIns(_ context.Context, accountID string) (int64, error) {
	return f.countDeleted(func(in fileSignIn) bool { return in.AccountID == accountID })
}

func (f *File) DeleteExpiredSignIns(context.Context) (int64, error) {
	now := Now()
	return f.countDeleted(func(in fileSignIn) bool { return !in.ExpiresAt.After(now) })
}

func (f *File) countDeleted(match func(fileSignIn) bool) (int64, error) {
	var n int64
	err := f.update(func(d *fileData) error {
		before := len(d.SignIns)
		d.SignIns = slices.DeleteFunc(d.SignIns, match)
		n = int64(before - len(d.SignIns))
		return nil
	})
	return n, err
}

// deleteSignIns removes what matches and, when one is required, reports none
// as ErrNotFound, as the one-row statements do.
func (f *File) deleteSignIns(match func(fileSignIn) bool, required bool) error {
	n, err := f.countDeleted(match)
	if err == nil && required && n == 0 {
		return ErrNotFound
	}
	return err
}
