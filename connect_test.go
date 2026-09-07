package main

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/ginuerzh/gosocks5"
)

// fakeSocks5 serves a single CONNECT request and relays the stream to the
// requested destination, propagating half-closes like a well-behaved proxy.
func fakeSocks5(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")

	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { ln.Close() })

	go func() {
		c, err := ln.Accept()

		if err != nil {
			return
		}

		conn := c.(*net.TCPConn)
		defer conn.Close()

		sc := gosocks5.ServerConn(conn, nil)

		if err := sc.Handleshake(); err != nil {
			return
		}

		req, err := gosocks5.ReadRequest(sc)

		if err != nil || req.Cmd != gosocks5.CmdConnect {
			return
		}

		d, err := net.Dial("tcp", req.Addr.String())

		if err != nil {
			gosocks5.NewReply(gosocks5.HostUnreachable, nil).Write(sc)

			return
		}

		dst := d.(*net.TCPConn)
		defer dst.Close()

		if err := gosocks5.NewReply(gosocks5.Succeeded, nil).Write(sc); err != nil {
			return
		}

		done := make(chan struct{}, 2)
		relay := func(w, r *net.TCPConn) {
			io.Copy(w, r)
			w.CloseWrite()
			done <- struct{}{}
		}

		go relay(dst, conn)
		go relay(conn, dst)

		<-done
		<-done
	}()

	return ln.Addr().String()
}

// A destination that answers only after it has seen EOF from the client, so
// the reply arrives only if the half-close travelled through the proxy.
func eofEchoServer(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")

	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { ln.Close() })

	go func() {
		c, err := ln.Accept()

		if err != nil {
			return
		}

		defer c.Close()

		c.SetDeadline(time.Now().Add(testTimeout))
		data, err := io.ReadAll(c)

		if err != nil {
			return
		}

		c.Write(append([]byte("echo:"), data...))
	}()

	return ln.Addr().String()
}

func TestSOCKS5ConnHalfClose(t *testing.T) {
	dst := eofEchoServer(t)
	proxy := fakeSocks5(t)
	connector := NewSOCKS5Connector(NewDirectConnector(), parseProxyURL(proxy))

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	conn, err := connector.DialContext(ctx, "tcp", dst)

	if err != nil {
		t.Fatal(err)
	}

	defer conn.Close()
	conn.SetDeadline(time.Now().Add(testTimeout))

	cw, ok := conn.(closeWriter)

	if !ok {
		t.Fatalf("%T does not support CloseWrite", conn)
	}

	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}

	if err := cw.CloseWrite(); err != nil {
		t.Fatal(err)
	}

	got, err := io.ReadAll(conn)

	if err != nil || string(got) != "echo:hello" {
		t.Fatalf("read %q, %v; want \"echo:hello\" and EOF", got, err)
	}
}

func TestSOCKS5ConnectRefused(t *testing.T) {
	proxy := fakeSocks5(t)
	connector := NewSOCKS5Connector(NewDirectConnector(), parseProxyURL(proxy))

	// nothing listens on the destination: the proxy must report a failure
	ln, err := net.Listen("tcp", "127.0.0.1:0")

	if err != nil {
		t.Fatal(err)
	}

	unused := ln.Addr().String()
	ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	if conn, err := connector.DialContext(ctx, "tcp", unused); err == nil {
		conn.Close()
		t.Fatal("dial to a closed port succeeded")
	}
}
