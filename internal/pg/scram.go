package pg

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// scramMaxIterations bounds the PBKDF2 work a server may ask of this client:
// PostgreSQL's default is 4096, and a count far past it is not a policy but a
// server spending the client's CPU.
const scramMaxIterations = 1 << 20

var errScramServer = errors.New("pg: the server could not prove it holds this role's verifier")

// scram is the client side of one SCRAM-SHA-256 exchange (RFC 5802, RFC 7677),
// the SASL mechanism PostgreSQL offers and the only one this client speaks.
// Without channel binding the gs2 header is "n,,", and the proof covers the
// client-first-bare, the server-first and the client-final-without-proof.
type scram struct {
	password    string
	nonce       string
	firstBare   string
	authMessage string
	serverKey   []byte
}

func newScram(user, password string) *scram {
	return newScramNonce(user, password, rand.Text())
}

func newScramNonce(user, password, nonce string) *scram {
	return &scram{password: password, nonce: nonce, firstBare: "n=" + saslName(user) + ",r=" + nonce}
}

func (s *scram) first() string {
	return "n,," + s.firstBare
}

// final answers the server's challenge with the proof and keeps the server
// key, so verify can hold the server to its half of the exchange.
func (s *scram) final(serverFirst string) (string, error) {
	attrs, err := scramAttrs(serverFirst)
	if err != nil {
		return "", err
	}
	nonce := attrs["r"]
	if !strings.HasPrefix(nonce, s.nonce) || len(nonce) == len(s.nonce) {
		return "", errors.New("pg: the server nonce does not extend the client nonce")
	}
	salt, err := base64.StdEncoding.Strict().DecodeString(attrs["s"])
	if err != nil || len(salt) == 0 {
		return "", errors.New("pg: malformed SCRAM salt")
	}
	iterations, err := strconv.Atoi(attrs["i"])
	if err != nil || iterations < 1 || iterations > scramMaxIterations {
		return "", fmt.Errorf("pg: SCRAM iteration count %q is not within 1 and %d", attrs["i"], scramMaxIterations)
	}
	salted, err := pbkdf2.Key(sha256.New, s.password, salt, iterations, sha256.Size)
	if err != nil {
		return "", err
	}
	defer clear(salted)
	clientKey := hmacSHA256(salted, []byte("Client Key"))
	defer clear(clientKey)
	storedKey := sha256.Sum256(clientKey)
	withoutProof := "c=biws,r=" + nonce
	s.authMessage = s.firstBare + "," + serverFirst + "," + withoutProof
	proof := hmacSHA256(storedKey[:], []byte(s.authMessage))
	subtle.XORBytes(proof, proof, clientKey)
	s.serverKey = hmacSHA256(salted, []byte("Server Key"))
	return withoutProof + ",p=" + base64.StdEncoding.EncodeToString(proof), nil
}

// verify holds the server to its signature; an unverified final would let a
// server that never knew the verifier pass as the one that does.
func (s *scram) verify(serverFinal string) error {
	attrs, err := scramAttrs(serverFinal)
	if err != nil {
		return err
	}
	if reason, refused := attrs["e"]; refused {
		return fmt.Errorf("pg: the server refused the proof: %s", reason)
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(attrs["v"])
	if err != nil {
		return errScramServer
	}
	if subtle.ConstantTimeCompare(signature, hmacSHA256(s.serverKey, []byte(s.authMessage))) != 1 {
		return errScramServer
	}
	return nil
}

// scramAttrs reads "k=v,k=v"; values are base64 or nonces, so a comma never
// occurs inside one and only the first '=' of a part separates.
func scramAttrs(message string) (map[string]string, error) {
	attrs := make(map[string]string)
	for part := range strings.SplitSeq(message, ",") {
		key, value, ok := strings.Cut(part, "=")
		if !ok || len(key) != 1 {
			return nil, errors.New("pg: malformed SCRAM message")
		}
		attrs[key] = value
	}
	return attrs, nil
}

// saslName escapes the two characters the attribute syntax reserves.
func saslName(name string) string {
	return strings.NewReplacer("=", "=3D", ",", "=2C").Replace(name)
}

func hmacSHA256(key, message []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}
