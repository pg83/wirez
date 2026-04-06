package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/ginuerzh/gosocks5/server"
)

func runServer(log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	listenAddr := fs.String("l", ":1080", "SOCKS5 server address")
	proxyFile := fs.String("f", "proxies.txt", "SOCKS5 proxies file")

	if err := fs.Parse(args); err != nil {
		return err
	}

	return Try(func() {
		f := Throw2(os.Open(*proxyFile))
		defer f.Close()

		socksAddrs := parseProxyFile(f)

		log.Info("starting listening", "addr", *listenAddr)

		ln := Throw2(net.Listen("tcp", *listenAddr))

		srv := &server.Server{
			Listener: ln,
		}

		dconn := NewDirectConnector()
		tcpProxies := make([]Connector, 0, len(socksAddrs))

		for _, socksAddr := range socksAddrs {
			socksConn := NewSOCKS5Connector(dconn, socksAddr)
			tcpProxies = append(tcpProxies, socksConn)
		}

		rotationTCPConn := NewRotationConnector(tcpProxies)
		udpProxies := make([]Connector, 0, len(socksAddrs))

		for _, socksAddr := range socksAddrs {
			socksConn := NewSOCKS5UDPConnector(log, dconn, dconn, socksAddr)
			udpProxies = append(udpProxies, socksConn)
		}

		rotationUDPConn := NewRotationConnector(udpProxies)

		go func() {
			ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer cancel()
			<-ctx.Done()

			if err := srv.Close(); err != nil {
				log.Error("error", "err", err)
			}
		}()

		err := srv.Serve(NewSOCKS5ServerHandler(log, rotationTCPConn, rotationUDPConn, NewTransporter(log)))

		if err != nil && !errors.Is(err, net.ErrClosed) {
			Throw(err)
		}
	}).AsError()
}
