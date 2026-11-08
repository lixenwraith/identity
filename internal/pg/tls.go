package pg

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
)

// TLSConfig verifies the server as serverName against the certificates in pem
// alone, the jail's own self-signed certificate or the issuer that signed it,
// and against the system roots when pem is empty: verify-full either way.
func TLSConfig(pem []byte, serverName string) (*tls.Config, error) {
	if serverName == "" {
		return nil, errors.New("pg: a server name is required to verify its certificate")
	}
	cfg := &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12}
	if len(pem) == 0 {
		return cfg, nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("pg: the CA file holds no certificate")
	}
	cfg.RootCAs = pool
	return cfg, nil
}
