package main

import (
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"
)

const testTimeout = 5 * time.Second

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// tcpPair returns both ends of a TCP connection over loopback.
func tcpPair(t *testing.T) (client, server *net.TCPConn) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")

	if err != nil {
		t.Fatal(err)
	}

	defer ln.Close()

	accepted := make(chan net.Conn, 1)

	go func() {
		c, err := ln.Accept()

		if err != nil {
			c = nil
		}

		accepted <- c
	}()

	c, err := net.Dial("tcp", ln.Addr().String())

	if err != nil {
		t.Fatal(err)
	}

	s := <-accepted

	if s == nil {
		c.Close()
		t.Fatal("accept failed")
	}

	client, server = c.(*net.TCPConn), s.(*net.TCPConn)
	deadline := time.Now().Add(testTimeout)
	client.SetDeadline(deadline)
	server.SetDeadline(deadline)

	t.Cleanup(func() {
		client.Close()
		server.Close()
	})

	return client, server
}

// eofEchoServer answers each connection only after it has seen EOF from the
// client, so the reply arrives only if a half-close travelled all the way.
func eofEchoServer(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")

	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()

			if err != nil {
				return
			}

			go func() {
				defer c.Close()

				c.SetDeadline(time.Now().Add(testTimeout))
				data, err := io.ReadAll(c)

				if err != nil {
					return
				}

				c.Write(append([]byte("echo:"), data...))
			}()
		}
	}()

	return ln.Addr().String()
}

// silentServer accepts connections and never says anything.
func silentServer(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")

	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()

			if err != nil {
				return
			}

			t.Cleanup(func() { c.Close() })
		}
	}()

	return ln.Addr().String()
}

// udpEchoServer sends every datagram back to its sender.
func udpEchoServer(t *testing.T) string {
	t.Helper()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")

	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { conn.Close() })

	go func() {
		buf := make([]byte, 64<<10)

		for {
			n, addr, err := conn.ReadFrom(buf)

			if err != nil {
				return
			}

			conn.WriteTo(buf[:n], addr)
		}
	}()

	return conn.LocalAddr().String()
}

// socks5TestConfig tunes a socks5TestServer; it is fixed at construction.
type socks5TestConfig struct {
	backend    string // CONNECT target override
	udpBackend string // UDP destination override
	user, pass string // require username/password authentication when set
	banner     []byte // sent in the same write as the CONNECT reply
}

// socks5TestServer is a small SOCKS5 server for tests. CONNECT relays to the
// requested destination, or to backend when set, and records what was asked
// for. UDP ASSOCIATE replies with an unspecified bind address, as some real
// proxies do, and relays datagrams to their destinations (or to udpBackend).
type socks5TestServer struct {
	socks5TestConfig

	t  *testing.T
	ln net.Listener

	mu           sync.Mutex
	connects     []string
	associations int
}

func newSocks5TestServer(t *testing.T, cfg socks5TestConfig) *socks5TestServer {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")

	if err != nil {
		t.Fatal(err)
	}

	s := &socks5TestServer{socks5TestConfig: cfg, t: t, ln: ln}
	t.Cleanup(func() { ln.Close() })

	go s.serve()

	return s
}

func (s *socks5TestServer) Addr() string {
	return s.ln.Addr().String()
}

func (s *socks5TestServer) Connects() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]string(nil), s.connects...)
}

func (s *socks5TestServer) Associations() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.associations
}

func (s *socks5TestServer) serve() {
	for {
		c, err := s.ln.Accept()

		if err != nil {
			return
		}

		go s.handle(c.(*net.TCPConn))
	}
}

func (s *socks5TestServer) handle(conn *net.TCPConn) {
	defer conn.Close()

	if !s.negotiate(conn) {
		return
	}

	var req [3]byte

	if _, err := io.ReadFull(conn, req[:]); err != nil {
		return
	}

	host, port, err := socks5ReadAddr(conn)

	if err != nil {
		return
	}

	switch req[1] {
	case socks5CmdConnect:
		s.connect(conn, net.JoinHostPort(host, itoa(port)))
	case socks5CmdUDPAssociate:
		s.associate(conn)
	default:
		conn.Write(socks5AppendAddr([]byte{socks5Version, 0x07, 0x00}, "0.0.0.0", 0))
	}
}

func (s *socks5TestServer) negotiate(conn net.Conn) bool {
	var head [2]byte

	if _, err := io.ReadFull(conn, head[:]); err != nil || head[0] != socks5Version {
		return false
	}

	methods := make([]byte, head[1])

	if _, err := io.ReadFull(conn, methods); err != nil {
		return false
	}

	if s.user == "" {
		conn.Write([]byte{socks5Version, socks5MethodNoAuth})

		return true
	}

	conn.Write([]byte{socks5Version, socks5MethodUserPass})

	var ver [2]byte

	if _, err := io.ReadFull(conn, ver[:]); err != nil {
		return false
	}

	gotUser := make([]byte, ver[1])
	io.ReadFull(conn, gotUser)

	var plen [1]byte
	io.ReadFull(conn, plen[:])

	gotPass := make([]byte, plen[0])
	io.ReadFull(conn, gotPass)

	if string(gotUser) != s.user || string(gotPass) != s.pass {
		conn.Write([]byte{socks5AuthVersion, 0x01})

		return false
	}

	conn.Write([]byte{socks5AuthVersion, 0x00})

	return true
}

func (s *socks5TestServer) connect(conn *net.TCPConn, target string) {
	s.mu.Lock()
	s.connects = append(s.connects, target)
	s.mu.Unlock()

	if s.backend != "" {
		target = s.backend
	}

	d, err := net.DialTimeout("tcp", target, testTimeout)

	if err != nil {
		conn.Write(socks5AppendAddr([]byte{socks5Version, 0x05, 0x00}, "0.0.0.0", 0))

		return
	}

	dst := d.(*net.TCPConn)
	defer dst.Close()

	reply := socks5AppendAddr([]byte{socks5Version, socks5Succeeded, 0x00}, "0.0.0.0", 0)
	// A proxy may well put the first bytes from the destination into the
	// same segment as its reply; a correct client must not lose them.
	conn.Write(append(reply, s.banner...))

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
}

func (s *socks5TestServer) associate(control net.Conn) {
	relay, err := net.ListenPacket("udp", "127.0.0.1:0")

	if err != nil {
		return
	}

	defer relay.Close()

	out, err := net.ListenPacket("udp", "127.0.0.1:0")

	if err != nil {
		return
	}

	defer out.Close()

	s.mu.Lock()
	s.associations++
	s.mu.Unlock()

	port := uint16(relay.LocalAddr().(*net.UDPAddr).Port)
	control.Write(socks5AppendAddr([]byte{socks5Version, socks5Succeeded, 0x00}, "0.0.0.0", port))

	var mu sync.Mutex
	var client net.Addr
	var requestedHost string
	var requestedPort uint16

	go func() {
		buf := make([]byte, 64<<10)

		for {
			n, from, err := relay.ReadFrom(buf)

			if err != nil {
				return
			}

			host, port, payload, err := socks5ParseUDPDatagram(buf[:n])

			if err != nil {
				continue
			}

			mu.Lock()
			client = from
			requestedHost, requestedPort = host, port
			mu.Unlock()

			target := net.JoinHostPort(host, itoa(port))

			if s.udpBackend != "" {
				target = s.udpBackend
			}

			dst, err := net.ResolveUDPAddr("udp", target)

			if err != nil {
				continue
			}

			out.WriteTo(payload, dst)
		}
	}()

	go func() {
		buf := make([]byte, 64<<10)

		for {
			n, from, err := out.ReadFrom(buf)

			if err != nil {
				return
			}

			mu.Lock()
			to := client
			host, port := requestedHost, requestedPort
			mu.Unlock()

			if to == nil {
				continue
			}

			// A real proxy relays to the requested destination, so replies
			// carry it; keep that up when the destination is overridden.
			if s.udpBackend == "" {
				src := from.(*net.UDPAddr)
				host, port = src.IP.String(), uint16(src.Port)
			}

			relay.WriteTo(socks5UDPDatagram(host, port, buf[:n]), to)
		}
	}()

	// the association lives exactly as long as the control connection
	io.Copy(io.Discard, control)
}

func itoa(port uint16) string {
	return net.JoinHostPort("", "")[0:0] + fmtUint(port)
}

func fmtUint(port uint16) string {
	var b [5]byte
	i := len(b)

	for {
		i--
		b[i] = byte('0' + port%10)
		port /= 10

		if port == 0 {
			break
		}
	}

	return string(b[i:])
}
