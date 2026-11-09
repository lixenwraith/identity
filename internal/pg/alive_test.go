package pg

import (
	"net"
	"testing"
	"time"
)

// An idle connection is probed before it is handed out: a quiet server is alive, a
// server that closed the socket or wrote unasked is not, each without reading what
// the next request would.
func TestAnIdleConnectionIsProbedWithoutReadingIt(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		for {
			server, err := listener.Accept()
			if err != nil {
				return
			}
			accepted <- server
		}
	}()
	open := func() (*conn, net.Conn) {
		t.Helper()
		client, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		return &conn{net: client}, <-accepted
	}
	quiet, server := open()
	defer server.Close()
	if !quiet.alive() {
		t.Fatal("a quiet server read as gone")
	}
	closed, server := open()
	_ = server.Close()
	time.Sleep(50 * time.Millisecond)
	if closed.alive() {
		t.Fatal("a closed socket read as alive")
	}
	noisy, server := open()
	defer server.Close()
	if _, err := server.Write([]byte("E")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if noisy.alive() {
		t.Fatal("bytes nobody asked for read as alive")
	}
	if !(&conn{net: pipeEnd()}).alive() {
		t.Fatal("a socket that cannot be asked was not taken as alive")
	}
}

func pipeEnd() net.Conn {
	a, _ := net.Pipe()
	return a
}
