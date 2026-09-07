package main

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func waitTransport(t *testing.T, done <-chan error) error {
	t.Helper()

	select {
	case err := <-done:
		return err
	case <-time.After(testTimeout):
		t.Fatal("Transport did not return")

		return nil
	}
}

// The app half-closes after sending its request, the upstream must see EOF
// and still be able to answer; only then does the relay finish.
func TestTransportPropagatesHalfClose(t *testing.T) {
	app, relayIn := tcpPair(t)
	relayOut, upstream := tcpPair(t)

	done := make(chan error, 1)

	go func() {
		done <- NewTransporter(discardLogger()).Transport(
			NewTimeoutConn(relayIn, time.Minute), NewTimeoutConn(relayOut, time.Minute))
	}()

	if _, err := app.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}

	if err := app.CloseWrite(); err != nil {
		t.Fatal(err)
	}

	got, err := io.ReadAll(upstream)

	if err != nil || string(got) != "request" {
		t.Fatalf("upstream read %q, %v; want \"request\" and EOF", got, err)
	}

	if _, err := upstream.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}

	if err := upstream.CloseWrite(); err != nil {
		t.Fatal(err)
	}

	got, err = io.ReadAll(app)

	if err != nil || string(got) != "response" {
		t.Fatalf("app read %q, %v; want \"response\" and EOF", got, err)
	}

	if err := waitTransport(t, done); err != nil {
		t.Errorf("Transport = %v, want nil", err)
	}
}

// Without CloseWrite on the other side EOF ends the whole relay at once.
func TestTransportEndsOnEOFWithoutHalfClose(t *testing.T) {
	app, relayIn := net.Pipe()
	relayOut, upstream := net.Pipe()

	t.Cleanup(func() {
		app.Close()
		relayIn.Close()
		relayOut.Close()
		upstream.Close()
	})

	done := make(chan error, 1)

	go func() {
		done <- NewTransporter(discardLogger()).Transport(relayIn, relayOut)
	}()

	go func() {
		app.Write([]byte("x"))
		app.Close()
	}()

	buf := make([]byte, 1)

	if _, err := io.ReadFull(upstream, buf); err != nil || buf[0] != 'x' {
		t.Fatalf("upstream read %q, %v", buf, err)
	}

	if err := waitTransport(t, done); err != nil {
		t.Errorf("Transport = %v, want nil", err)
	}
}

func TestTransportReportsReadError(t *testing.T) {
	_, relayIn := tcpPair(t)
	relayOut, _ := tcpPair(t)

	done := make(chan error, 1)

	go func() {
		done <- NewTransporter(discardLogger()).Transport(relayIn, relayOut)
	}()

	relayIn.Close()

	if err := waitTransport(t, done); err == nil {
		t.Error("Transport = nil, want the read error")
	}
}

func TestTimeoutConnCloseWrite(t *testing.T) {
	client, server := tcpPair(t)

	if err := NewTimeoutConn(client, time.Minute).CloseWrite(); err != nil {
		t.Fatal(err)
	}

	if got, err := io.ReadAll(server); err != nil || len(got) != 0 {
		t.Errorf("server read %q, %v; want EOF", got, err)
	}

	p1, p2 := net.Pipe()
	defer p1.Close()
	defer p2.Close()

	if err := NewTimeoutConn(p1, time.Minute).CloseWrite(); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("CloseWrite on a pipe = %v, want ErrUnsupported", err)
	}
}
