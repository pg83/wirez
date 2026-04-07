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

type Transporter interface {
	Transport(rw1, rw2 io.ReadWriter) error
}

func NewTransporter(log *slog.Logger) Transporter {
	return &transporter{log}
}

type transporter struct {
	log *slog.Logger
}

func (t *transporter) Transport(rw1, rw2 io.ReadWriter) error {
	errc := make(chan error, 1)
	copyBuf := func(w io.Writer, r io.Reader) {
		_, err := io.Copy(w, r)
		errc <- err
	}

	go copyBuf(rw1, rw2)
	go copyBuf(rw2, rw1)

	err := <-errc

	t.log.Debug("close connection", "err", err)
	var terr timeoutError

	if err == io.EOF || (errors.As(err, &terr) && terr.Timeout()) {
		err = nil
	}

	return err
}

type timeoutError interface {
	error
	Timeout() bool
}
