package pg

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	protocolVersion = 3 << 16
	sslRequestCode  = 80877103
	saslMechanism   = "SCRAM-SHA-256"
	// maxMessage bounds one backend message; a row of this schema is under a
	// kilobyte, and a server announcing more is not one to allocate for.
	maxMessage = 16 << 20

	authOK           = 0
	authSASL         = 10
	authSASLContinue = 11
	authSASLFinal    = 12
)

var errTerminated = errors.New("pg: the connection was closed")

// conn is one authenticated connection, used by one goroutine at a time:
// the pool hands it out and takes it back, a transaction holds it.
type conn struct {
	net    net.Conn
	r      *bufio.Reader
	w      *bufio.Writer
	buf    []byte
	lenAt  int
	status byte
	broken bool
}

// result is what one round trip returned: the rows of the last result set,
// NULL as a nil column, and the last command's completion tag.
type result struct {
	columns int
	rows    [][][]byte
	tag     string
}

// dial connects, upgrades to TLS, authenticates and reads the server's
// greeting, all within ConnectTimeout, so a dead or misconfigured server is
// an error at Open and never a hang.
func dial(ctx context.Context, cfg Config) (*conn, error) {
	raw, err := (&net.Dialer{Timeout: cfg.ConnectTimeout}).DialContext(ctx, "tcp", net.JoinHostPort(cfg.Host, cfg.Port))
	if err != nil {
		return nil, err
	}
	c := &conn{net: raw}
	_ = raw.SetDeadline(time.Now().Add(cfg.ConnectTimeout))
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	err = c.startup(ctx, cfg)
	if !stop() || err != nil && ctx.Err() != nil {
		err = ctx.Err()
	}
	if err != nil {
		_ = c.net.Close()
		return nil, err
	}
	_ = c.net.SetDeadline(time.Time{})
	return c, nil
}

func (c *conn) startup(ctx context.Context, cfg Config) error {
	var request [8]byte
	binary.BigEndian.PutUint32(request[:4], 8)
	binary.BigEndian.PutUint32(request[4:], sslRequestCode)
	if _, err := c.net.Write(request[:]); err != nil {
		return err
	}
	var answer [1]byte
	if _, err := io.ReadFull(c.net, answer[:]); err != nil {
		return err
	}
	if answer[0] != 'S' {
		return errors.New("pg: the server declines SSL; this client speaks TLS alone")
	}
	secured := tls.Client(c.net, cfg.TLS)
	if err := secured.HandshakeContext(ctx); err != nil {
		return err
	}
	c.net = secured
	c.r = bufio.NewReaderSize(secured, 32<<10)
	c.w = bufio.NewWriterSize(secured, 32<<10)

	// The output settings the scanners assume ride in the startup message, so
	// a role or database setting cannot change what a row looks like.
	c.begin(0)
	c.int32(protocolVersion)
	for _, kv := range [][2]string{
		{"user", cfg.User}, {"database", cfg.Database}, {"application_name", "identity"},
		{"client_encoding", "UTF8"}, {"DateStyle", "ISO"}, {"TimeZone", "UTC"}, {"bytea_output", "hex"},
	} {
		c.cstring(kv[0])
		c.cstring(kv[1])
	}
	c.buf = append(c.buf, 0)
	c.end()
	if err := c.flush(); err != nil {
		return err
	}
	return c.authenticate(cfg)
}

// authenticate runs the SASL exchange and admits nothing else: a server that
// grants the role without a proof, or asks for a password in the clear or an
// MD5 hash, is not the server this client was configured for.
func (c *conn) authenticate(cfg Config) error {
	exchange := newScram(cfg.User, cfg.Password)
	proven := false
	for {
		typ, body, err := c.read()
		if err != nil {
			return err
		}
		switch typ {
		case 'E':
			return parseError(body)
		case 'R':
			if len(body) < 4 {
				return errors.New("pg: malformed authentication message")
			}
			switch kind := binary.BigEndian.Uint32(body); kind {
			case authSASL:
				if !offersSCRAM(body[4:]) {
					return errors.New("pg: the server offers no SCRAM-SHA-256")
				}
				first := exchange.first()
				c.begin('p')
				c.cstring(saslMechanism)
				c.int32(int32(len(first)))
				c.buf = append(c.buf, first...)
				c.end()
				if err := c.flush(); err != nil {
					return err
				}
			case authSASLContinue:
				final, err := exchange.final(string(body[4:]))
				if err != nil {
					return err
				}
				c.begin('p')
				c.buf = append(c.buf, final...)
				c.end()
				if err := c.flush(); err != nil {
					return err
				}
			case authSASLFinal:
				if err := exchange.verify(string(body[4:])); err != nil {
					return err
				}
				proven = true
			case authOK:
				if !proven {
					return errors.New("pg: the server admitted the role without SCRAM-SHA-256")
				}
			default:
				return fmt.Errorf("pg: the server asks for authentication %d; this client speaks SCRAM-SHA-256 alone", kind)
			}
		case 'S', 'N', 'K':
		case 'Z':
			if len(body) != 1 {
				return errors.New("pg: malformed ReadyForQuery")
			}
			c.status = body[0]
			return nil
		default:
			return fmt.Errorf("pg: unexpected message %q before the first query", typ)
		}
	}
}

func offersSCRAM(list []byte) bool {
	for _, name := range bytes.Split(list, []byte{0}) {
		if string(name) == saslMechanism {
			return true
		}
	}
	return false
}

// query sends one statement and reads its whole answer: a simple query when
// nothing is bound, so a migration's several statements run as one; otherwise
// parsed and bound unnamed in the extended protocol, parameters and results
// in the text format.
func (c *conn) query(ctx context.Context, sql string, args []any) (*result, error) {
	if c.broken {
		return nil, errTerminated
	}
	if len(args) == 0 {
		c.begin('Q')
		c.cstring(sql)
		c.end()
	} else {
		params := make([][]byte, len(args))
		for i, arg := range args {
			p, err := encodeArg(arg)
			if err != nil {
				c.buf = c.buf[:0]
				return nil, fmt.Errorf("%w (parameter %d)", err, i+1)
			}
			params[i] = p
		}
		c.begin('P')
		c.cstring("")
		c.cstring(sql)
		c.int16(0)
		c.end()
		c.begin('B')
		c.cstring("")
		c.cstring("")
		c.int16(0)
		c.int16(int16(len(params)))
		for _, p := range params {
			if p == nil {
				c.int32(-1)
				continue
			}
			c.int32(int32(len(p)))
			c.buf = append(c.buf, p...)
		}
		c.int16(0)
		c.end()
		c.begin('D')
		c.buf = append(c.buf, 'P')
		c.cstring("")
		c.end()
		c.begin('E')
		c.cstring("")
		c.int32(0)
		c.end()
		c.begin('S')
		c.end()
	}
	return c.roundTrip(ctx)
}

// roundTrip flushes what is buffered and reads to ReadyForQuery. A cancelled
// context closes the socket, which ends the read; the server notices on its
// next write and the pool discards the connection.
func (c *conn) roundTrip(ctx context.Context) (*result, error) {
	// The socket's own deadline is a backstop behind the context's, so a
	// statement that outlives its context fails as the context's error.
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.net.SetDeadline(deadline.Add(time.Second))
	}
	stop := context.AfterFunc(ctx, func() { _ = c.net.Close() })
	res, err := c.exchange()
	if !stop() || err != nil && ctx.Err() != nil {
		err = ctx.Err()
	}
	if err != nil {
		c.broken = true
		_ = c.net.Close()
		return nil, err
	}
	_ = c.net.SetDeadline(time.Time{})
	return res, nil
}

func (c *conn) exchange() (*result, error) {
	if err := c.flush(); err != nil {
		return nil, err
	}
	res := &result{}
	var failure error
	for {
		typ, body, err := c.read()
		if err != nil {
			return nil, err
		}
		switch typ {
		case 'T':
			if len(body) < 2 {
				return nil, errors.New("pg: malformed RowDescription")
			}
			res.columns = int(binary.BigEndian.Uint16(body))
			res.rows = nil
		case 'D':
			row, err := parseRow(body)
			if err != nil {
				return nil, err
			}
			res.rows = append(res.rows, row)
		case 'C':
			res.tag = string(bytes.TrimSuffix(body, []byte{0}))
		case 'E':
			if failure == nil {
				failure = parseError(body)
			}
		case 'Z':
			if len(body) != 1 {
				return nil, errors.New("pg: malformed ReadyForQuery")
			}
			c.status = body[0]
			if failure != nil {
				return nil, failure
			}
			return res, nil
		case '1', '2', 'n', 'I', 'N', 'S', 's':
		default:
			return nil, fmt.Errorf("pg: unexpected message %q in a query's answer", typ)
		}
	}
}

func (c *conn) read() (byte, []byte, error) {
	var head [5]byte
	if _, err := io.ReadFull(c.r, head[:]); err != nil {
		return 0, nil, err
	}
	n := int64(binary.BigEndian.Uint32(head[1:])) - 4
	if n < 0 || n > maxMessage {
		return 0, nil, fmt.Errorf("pg: message %q announces %d bytes", head[0], n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(c.r, body); err != nil {
		return 0, nil, err
	}
	return head[0], body, nil
}

// close says goodbye when the connection is whole, so the server logs no
// unexpected EOF, and drops the socket either way.
func (c *conn) close() {
	if !c.broken {
		_ = c.net.SetDeadline(time.Now().Add(time.Second))
		c.begin('X')
		c.end()
		_ = c.flush()
	}
	_ = c.net.Close()
}

func (c *conn) begin(typ byte) {
	if typ != 0 {
		c.buf = append(c.buf, typ)
	}
	c.lenAt = len(c.buf)
	c.buf = append(c.buf, 0, 0, 0, 0)
}

func (c *conn) end() {
	binary.BigEndian.PutUint32(c.buf[c.lenAt:], uint32(len(c.buf)-c.lenAt))
}

func (c *conn) int16(v int16) { c.buf = binary.BigEndian.AppendUint16(c.buf, uint16(v)) }
func (c *conn) int32(v int32) { c.buf = binary.BigEndian.AppendUint32(c.buf, uint32(v)) }

func (c *conn) cstring(s string) {
	c.buf = append(c.buf, s...)
	c.buf = append(c.buf, 0)
}

func (c *conn) flush() error {
	_, err := c.w.Write(c.buf)
	c.buf = c.buf[:0]
	if err != nil {
		return err
	}
	return c.w.Flush()
}

func parseRow(body []byte) ([][]byte, error) {
	if len(body) < 2 {
		return nil, errors.New("pg: malformed DataRow")
	}
	row := make([][]byte, binary.BigEndian.Uint16(body))
	body = body[2:]
	for i := range row {
		if len(body) < 4 {
			return nil, errors.New("pg: malformed DataRow")
		}
		n := int32(binary.BigEndian.Uint32(body))
		body = body[4:]
		if n == -1 {
			continue
		}
		if n < 0 || int(n) > len(body) {
			return nil, errors.New("pg: malformed DataRow")
		}
		row[i] = body[:n:n]
		body = body[n:]
	}
	return row, nil
}

// parseError reads ErrorResponse's fields: V is the severity in English where
// S may be localized, C the SQLSTATE, M and D the message and detail, n the
// constraint a violation names.
func parseError(body []byte) *Error {
	e := &Error{}
	for len(body) > 1 && body[0] != 0 {
		end := bytes.IndexByte(body[1:], 0)
		if end < 0 {
			break
		}
		value := string(body[1 : 1+end])
		switch body[0] {
		case 'V':
			e.Severity = value
		case 'S':
			if e.Severity == "" {
				e.Severity = value
			}
		case 'C':
			e.Code = value
		case 'M':
			e.Message = value
		case 'D':
			e.Detail = value
		case 'n':
			e.Constraint = value
		}
		body = body[2+end:]
	}
	return e
}

// rowsAffected reads the count off a completion tag such as "UPDATE 3" or
// "INSERT 0 1"; a tag without one, "BEGIN" or "CREATE TABLE", is zero rows.
func rowsAffected(tag string) int64 {
	verb, rest, ok := strings.Cut(tag, " ")
	if !ok {
		return 0
	}
	switch verb {
	case "INSERT", "UPDATE", "DELETE", "MERGE", "SELECT", "MOVE", "FETCH", "COPY":
		n, _ := strconv.ParseInt(rest[strings.LastIndexByte(rest, ' ')+1:], 10, 64)
		return n
	}
	return 0
}
