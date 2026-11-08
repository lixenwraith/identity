package pg

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"
)

func TestAURLNamesTheServerAndNeverThePassword(t *testing.T) {
	cfg, err := ParseURL("postgres://identity@db.example.test/identity?sslmode=verify-full")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Host != "db.example.test" || cfg.Port != "5432" || cfg.Database != "identity" || cfg.User != "identity" {
		t.Fatalf("parsed %+v", cfg)
	}
	if cfg.MaxConns != DefaultMaxConns || cfg.ConnectTimeout != DefaultConnectTimeout {
		t.Fatalf("defaults not applied: %+v", cfg)
	}
	if cfg, err := ParseURL("postgresql://identity@[fd00::10]:5433/identity"); err != nil || cfg.Host != "fd00::10" || cfg.Port != "5433" {
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
		if _, err := ParseURL(raw); err == nil {
			t.Errorf("%q was accepted", raw)
		}
	}
}

func TestOpenChecksTheConfigBeforeDialling(t *testing.T) {
	cfg, _ := ParseURL("postgres://identity@db.example.test/identity")
	if _, err := Open(context.Background(), cfg); err == nil || errors.Is(err, ErrNotImplemented) {
		t.Fatalf("a config without a password or TLS was not refused: %v", err)
	}
}

func TestTLSTrustsTheGivenCertificateAlone(t *testing.T) {
	if _, err := TLSConfig(nil, ""); err == nil {
		t.Fatal("an empty server name was accepted")
	}
	cfg, err := TLSConfig(nil, "db.example.test")
	if err != nil || cfg.RootCAs != nil || cfg.ServerName != "db.example.test" {
		t.Fatalf("system roots: %+v, %v", cfg, err)
	}
	if _, err := TLSConfig([]byte("not a certificate"), "db.example.test"); err == nil {
		t.Fatal("a CA file without a certificate was accepted")
	}
	cfg, err = TLSConfig(selfSigned(t), "db.example.test")
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
