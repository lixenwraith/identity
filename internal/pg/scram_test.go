package pg

import (
	"strings"
	"testing"
)

// The exchange of RFC 7677 §3: user "user", password "pencil", both nonces given.
const (
	rfcNonce       = "rOprNGfwEbeRWgbNEkqO"
	rfcServerFirst = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"
	rfcClientFinal = "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
	rfcServerFinal = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="
)

func TestTheExchangeMatchesRFC7677(t *testing.T) {
	s := newScramNonce("user", "pencil", rfcNonce)
	if got := s.first(); got != "n,,n=user,r="+rfcNonce {
		t.Fatalf("client first = %q", got)
	}
	got, err := s.final(rfcServerFirst)
	if err != nil {
		t.Fatal(err)
	}
	if got != rfcClientFinal {
		t.Fatalf("client final = %q, want %q", got, rfcClientFinal)
	}
	if err := s.verify(rfcServerFinal); err != nil {
		t.Fatal(err)
	}
}

func TestAForgedServerSignatureIsRefused(t *testing.T) {
	s := newScramNonce("user", "pencil", rfcNonce)
	if _, err := s.final(rfcServerFirst); err != nil {
		t.Fatal(err)
	}
	if err := s.verify("v=7rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="); err == nil {
		t.Fatal("a wrong server signature verified")
	}
	if err := s.verify("e=invalid-proof"); err == nil || !strings.Contains(err.Error(), "invalid-proof") {
		t.Fatalf("a server error was not reported: %v", err)
	}
}

func TestAServerNonceMustExtendTheClients(t *testing.T) {
	for _, serverFirst := range []string{
		"r=" + rfcNonce + ",s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
		"r=someoneelse" + rfcNonce + ",s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
		"r=" + rfcNonce + "x,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=0",
		"r=" + rfcNonce + "x,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=99999999",
		"r=" + rfcNonce + "x,s=not base64!,i=4096",
		"garbage",
	} {
		s := newScramNonce("user", "pencil", rfcNonce)
		if _, err := s.final(serverFirst); err == nil {
			t.Errorf("%q was accepted", serverFirst)
		}
	}
}

func TestAUserNameIsEscaped(t *testing.T) {
	if got := newScramNonce("a=b,c", "x", "n").first(); got != "n,,n=a=3Db=2Cc,r=n" {
		t.Fatalf("client first = %q", got)
	}
}
