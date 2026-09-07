package main

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"time"
)

type TimeoutConn struct {
	net.Conn
	// specifies max amount of time to wait for Read/Write calls to complete
	IOTimeout time.Duration
}

func NewTimeoutConn(conn net.Conn, ioTimeout time.Duration) *TimeoutConn {
	return &TimeoutConn{Conn: conn, IOTimeout: ioTimeout}
}

func (c *TimeoutConn) Read(b []byte) (n int, err error) {
	if err = c.SetDeadline(time.Now().Add(c.IOTimeout)); err != nil {
		return
	}

	return c.Conn.Read(b)
}

func (c *TimeoutConn) Write(b []byte) (n int, err error) {
	if err = c.SetDeadline(time.Now().Add(c.IOTimeout)); err != nil {
		return
	}

	return c.Conn.Write(b)
}

// CloseWrite half-closes the wrapped connection when it supports that.
func (c *TimeoutConn) CloseWrite() error {
	if cw, ok := c.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}

	return errors.ErrUnsupported
}

// closeWriter is implemented by stream connections that can shut down their
// sending side alone (net.TCPConn, gonet.TCPConn, TimeoutConn, socks5Conn).
type closeWriter interface {
	CloseWrite() error
}

type Transporter interface {
	Transport(rw1, rw2 io.ReadWriter) error
}

func NewTransporter(log *slog.Logger) Transporter {
	return &transporter{log}
}

type transporter struct {
	log *slog.Logger
}

// Transport relays data between rw1 and rw2 in both directions. EOF on one
// side is propagated to the other as a half-close, and the relay keeps
// running the other way until that side finishes as well, so protocols that
// shut down their sending side and then wait for the reply keep working. A
// side that cannot half-close, or any error, ends the relay right away;
// closing the connections is left to the caller.
func (t *transporter) Transport(rw1, rw2 io.ReadWriter) error {
	errc := make(chan error, 2)

	go t.relay(rw1, rw2, errc)
	go t.relay(rw2, rw1, errc)

	err := <-errc

	if err == nil {
		// half-closed, wait for the other direction to finish
		err = <-errc
	}

	t.log.Debug("close connection", "err", err)
	var terr timeoutError

	if err == io.EOF || (errors.As(err, &terr) && terr.Timeout()) {
		err = nil
	}

	return err
}

// relay copies r into w until EOF or an error. On EOF it half-closes w and
// reports nil when that worked, io.EOF otherwise so that Transport stops.
func (t *transporter) relay(w io.Writer, r io.Reader, errc chan<- error) {
	_, err := io.Copy(w, r)

	if err == nil {
		err = io.EOF

		if cw, ok := w.(closeWriter); ok && cw.CloseWrite() == nil {
			err = nil
		}
	}

	errc <- err
}

type timeoutError interface {
	error
	Timeout() bool
}
