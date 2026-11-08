package pg

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// Parameters go as text in the forms the server parses for any type: bytea
// in the hex form, a time as ISO 8601 with its offset to the microsecond the
// server keeps, nil and a nil pointer as NULL.
func encodeArg(arg any) ([]byte, error) {
	switch v := arg.(type) {
	case nil:
		return nil, nil
	case string:
		return []byte(v), nil
	case *string:
		if v == nil {
			return nil, nil
		}
		return []byte(*v), nil
	case []byte:
		if v == nil {
			return nil, nil
		}
		out := make([]byte, 2+hex.EncodedLen(len(v)))
		out[0], out[1] = '\\', 'x'
		hex.Encode(out[2:], v)
		return out, nil
	case bool:
		if v {
			return []byte("t"), nil
		}
		return []byte("f"), nil
	case int:
		return strconv.AppendInt(nil, int64(v), 10), nil
	case int32:
		return strconv.AppendInt(nil, int64(v), 10), nil
	case int64:
		return strconv.AppendInt(nil, v, 10), nil
	case uint8:
		return strconv.AppendUint(nil, uint64(v), 10), nil
	case uint32:
		return strconv.AppendUint(nil, uint64(v), 10), nil
	case time.Time:
		return []byte(v.UTC().Format("2006-01-02T15:04:05.999999Z07:00")), nil
	case *time.Time:
		if v == nil {
			return nil, nil
		}
		return encodeArg(*v)
	}
	return nil, fmt.Errorf("pg: a %T cannot be a parameter", arg)
}

// The server prints these under the startup message's DateStyle and TimeZone:
// ISO, UTC, a space before the time and the offset in hours, with minutes and
// seconds only when a zone has them.
var timeLayouts = []string{
	"2006-01-02 15:04:05-07",
	"2006-01-02 15:04:05-07:00",
	"2006-01-02 15:04:05-07:00:00",
	"2006-01-02 15:04:05",
}

// scanText converts one text column into dest. A NULL goes into a pointer to
// a pointer alone, as nil, and fails any other destination, so a column that
// may be NULL is declared so where it is read.
func scanText(src []byte, dest any) error {
	if src == nil {
		switch d := dest.(type) {
		case **time.Time:
			*d = nil
		case **string:
			*d = nil
		default:
			return fmt.Errorf("pg: a NULL cannot be scanned into a %T", dest)
		}
		return nil
	}
	var err error
	switch d := dest.(type) {
	case *string:
		*d = string(src)
	case **string:
		s := string(src)
		*d = &s
	case *[]byte:
		*d, err = decodeBytea(src)
	case *bool:
		switch string(src) {
		case "t":
			*d = true
		case "f":
			*d = false
		default:
			err = fmt.Errorf("pg: %q is not a boolean", src)
		}
	case *int:
		var n int64
		n, err = strconv.ParseInt(string(src), 10, strconv.IntSize)
		*d = int(n)
	case *int32:
		var n int64
		n, err = strconv.ParseInt(string(src), 10, 32)
		*d = int32(n)
	case *int64:
		*d, err = strconv.ParseInt(string(src), 10, 64)
	case *uint8:
		var n uint64
		n, err = strconv.ParseUint(string(src), 10, 8)
		*d = uint8(n)
	case *uint32:
		var n uint64
		n, err = strconv.ParseUint(string(src), 10, 32)
		*d = uint32(n)
	case *time.Time:
		*d, err = parseTime(string(src))
	case **time.Time:
		var t time.Time
		if t, err = parseTime(string(src)); err == nil {
			*d = &t
		}
	default:
		return fmt.Errorf("pg: cannot scan into a %T", dest)
	}
	return err
}

func decodeBytea(src []byte) ([]byte, error) {
	if len(src) < 2 || src[0] != '\\' || src[1] != 'x' {
		return nil, errors.New("pg: bytea is not in the hex form")
	}
	out := make([]byte, hex.DecodedLen(len(src)-2))
	if _, err := hex.Decode(out, src[2:]); err != nil {
		return nil, fmt.Errorf("pg: malformed bytea: %w", err)
	}
	return out, nil
}

func parseTime(s string) (time.Time, error) {
	for _, layout := range timeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("pg: %q is not a timestamp this client reads", s)
}
