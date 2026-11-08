package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"text/tabwriter"

	"github.com/lixenwraith/identity/internal/config"
	"github.com/lixenwraith/identity/internal/pg"
	"github.com/lixenwraith/identity/internal/store"

	"github.com/lixenwraith/auth"
)

const cliUsage = `Usage: identity migrate [flags]
       identity account add|disable|enable|reset|list|delete [<name>] [flags]

The operator's commands over the store, with the service's database flags.
add and reset read the password from the terminal, or from standard input
when it is not one; the service loads a new or reset credential at its next
start.`

var errUsage = errors.New("usage")

// cli runs one operator command: args[0] names it, the flags follow the
// subcommand and its name. The result is printed to stdout, a password is
// read from stdin, and the usage and errors go to stderr.
func cli(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	var verb, name string
	flags := args[1:]
	if args[0] == "account" {
		if len(flags) == 0 {
			fmt.Fprintln(stderr, cliUsage)
			return errUsage
		}
		verb, flags = flags[0], flags[1:]
		if verb != "list" {
			if len(flags) == 0 || strings.HasPrefix(flags[0], "-") {
				fmt.Fprintf(stderr, "identity account %s: a name is required\n", verb)
				return errUsage
			}
			name, flags = flags[0], flags[1:]
		}
	}
	cfg, err := config.Parse(flags, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stderr, cliUsage)
		}
		return err
	}
	dbCfg, err := database(cfg)
	if err != nil {
		return err
	}
	openCtx, cancel := context.WithTimeout(ctx, openTimeout)
	pool, err := pg.Open(openCtx, dbCfg)
	cancel()
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer pool.Close()
	st := store.New(pool)
	if args[0] == "migrate" {
		from, to, err := st.Migrate(ctx)
		if err != nil {
			return err
		}
		if from == to {
			fmt.Fprintf(stdout, "schema at version %d, nothing to apply\n", to)
		} else {
			fmt.Fprintf(stdout, "schema migrated from version %d to %d\n", from, to)
		}
		return nil
	}
	if err := st.CheckSchema(ctx); err != nil {
		return fmt.Errorf("%w; run identity migrate", err)
	}
	return account(ctx, st, cfg, verb, name, stdin, stdout, stderr)
}

func account(ctx context.Context, st *store.Store, cfg config.Config, verb, name string, stdin io.Reader, stdout, stderr io.Writer) error {
	if verb == "list" {
		list, err := st.Accounts(ctx)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(stdout, 0, 8, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tNAME\tCREATED\tSTATE")
		for _, a := range list {
			state := "enabled"
			if a.DisabledAt != nil {
				state = "disabled " + a.DisabledAt.Format("2006-01-02")
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", a.ID, a.Name, a.CreatedAt.Format("2006-01-02"), state)
		}
		return tw.Flush()
	}
	name, err := store.NormalizeName(name)
	if err != nil {
		return err
	}
	if verb == "add" {
		cred, err := credential(name, cfg.KDF, stdin, stderr)
		if err != nil {
			return err
		}
		a, err := st.CreateAccount(ctx, name, store.VerifierOf("", cred), cfg.MaxAccounts)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "created %s %s; the service loads it at its next start\n", a.ID, a.Name)
		return nil
	}
	a, err := st.AccountByName(ctx, name)
	if err != nil {
		return fmt.Errorf("account %q: %w", name, err)
	}
	switch verb {
	case "disable", "enable":
		if err := st.SetDisabled(ctx, a.ID, verb == "disable"); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "%sd %s\n", verb, a.Name)
	case "reset":
		cred, err := credential(name, cfg.KDF, stdin, stderr)
		if err != nil {
			return err
		}
		if err := st.SetVerifier(ctx, store.VerifierOf(a.ID, cred)); err != nil {
			return err
		}
		n, err := st.DeleteSignIns(ctx, a.ID)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "reset %s: a new credential, %d sign-ins deleted; the service takes it at its next start\n", a.Name, n)
	case "delete":
		if err := st.DeleteAccount(ctx, a.ID); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "deleted %s %s with its sign-ins\n", a.ID, a.Name)
	default:
		fmt.Fprintln(stderr, cliUsage)
		return errUsage
	}
	return nil
}

// credential derives the one server-side Argon2 of the service under the
// configured profile, from a password that never reaches an argument.
func credential(name string, kdf config.KDF, stdin io.Reader, stderr io.Writer) (*auth.Credential, error) {
	password, err := readPassword(stdin, stderr, "Password for "+name+": ")
	if err != nil {
		return nil, err
	}
	if f, ok := stdin.(*os.File); ok && isTerminal(f) {
		again, err := readPassword(stdin, stderr, "Repeat: ")
		if err != nil {
			return nil, err
		}
		if again != password {
			return nil, errors.New("the passwords differ")
		}
	}
	return auth.NewCredential(name, password, auth.WithMemory(kdf.Memory), auth.WithTime(kdf.Time), auth.WithThreads(kdf.Threads))
}

// readPassword takes one line: prompted without echo on a terminal, read as
// given from a pipe or a file.
func readPassword(stdin io.Reader, stderr io.Writer, prompt string) (string, error) {
	f, ok := stdin.(*os.File)
	if ok && isTerminal(f) {
		fmt.Fprint(stderr, prompt)
		echo(f, false)
		defer func() {
			echo(f, true)
			fmt.Fprintln(stderr)
		}()
	}
	line, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && (!errors.Is(err, io.EOF) || line == "") {
		return "", errors.New("no password was given")
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// echo turns the terminal's echo off while a password is typed, through
// stty, which every POSIX system has, since the standard library has no
// termios of its own.
func echo(f *os.File, on bool) {
	arg := "-echo"
	if on {
		arg = "echo"
	}
	cmd := exec.Command("stty", arg)
	cmd.Stdin = f
	_ = cmd.Run()
}
