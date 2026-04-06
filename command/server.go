package command

import (
	"context"
	"errors"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/ginuerzh/gosocks5/server"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/v-byte-cpu/wirez/pkg/connect"
	"github.com/v-byte-cpu/wirez/pkg/throw"
)

func newServerCmd(log *zerolog.Logger) *serverCmd {
	c := &serverCmd{}

	cmd := &cobra.Command{
		Use:     "server [flags]",
		Example: "server -l 127.0.0.1:1080 -f proxies.txt",
		Short:   "Start SOCKS5 server to load-balance requests",
		RunE: func(cmd *cobra.Command, args []string) error {
			return throw.Try(func() {
				f := throw.Throw2(os.Open(c.opts.proxyFile))
				defer f.Close()
				socksAddrs := parseProxyFile(f)

				log.Info().Msgf("starting listening on %s...", c.opts.listenAddr)
				ln := throw.Throw2(net.Listen("tcp", c.opts.listenAddr))
				srv := &server.Server{
					Listener: ln,
				}

				dconn := connect.NewDirectConnector()
				tcpProxies := make([]connect.Connector, 0, len(socksAddrs))
				for _, socksAddr := range socksAddrs {
					socksConn := connect.NewSOCKS5Connector(dconn, socksAddr)
					tcpProxies = append(tcpProxies, socksConn)
				}
				rotationTCPConn := connect.NewRotationConnector(tcpProxies)

				udpProxies := make([]connect.Connector, 0, len(socksAddrs))
				for _, socksAddr := range socksAddrs {
					socksConn := connect.NewSOCKS5UDPConnector(log, dconn, dconn, socksAddr)
					udpProxies = append(udpProxies, socksConn)
				}
				rotationUDPConn := connect.NewRotationConnector(udpProxies)

				go func() {
					ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
					defer cancel()
					<-ctx.Done()
					if err := srv.Close(); err != nil {
						log.Error().Err(err).Msg("")
					}
				}()

				err := srv.Serve(connect.NewSOCKS5ServerHandler(log, rotationTCPConn, rotationUDPConn, connect.NewTransporter(log)))
				if err != nil && !errors.Is(err, net.ErrClosed) {
					throw.Throw(err)
				}
			}).AsError()
		},
	}

	c.opts.initCliFlags(cmd)

	c.cmd = cmd
	return c
}

type serverCmd struct {
	cmd  *cobra.Command
	opts serverCmdOpts
}

type serverCmdOpts struct {
	listenAddr string
	proxyFile  string
}

func (o *serverCmdOpts) initCliFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&o.listenAddr, "listen", "l", ":1080", "SOCKS5 server address")
	cmd.Flags().StringVarP(&o.proxyFile, "file", "f", "proxies.txt", "SOCKS5 proxies file")
}
