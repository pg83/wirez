//go:build linux

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"log/slog"

	"github.com/spf13/cobra"
	"go.uber.org/multierr"
	"golang.org/x/sys/unix"
)

func newRunCmd(log *slog.Logger) *runCmd {
	c := &runCmd{}

	cmd := &cobra.Command{
		Use: "run [flags] command",
		Example: strings.Join([]string{
			"wirez run -F 127.0.0.1:1234 bash",
			"wirez run -F 127.0.0.1:1234 -L 53:1.1.1.1:53/udp -- curl example.com"}, "\n"),
		Short: "Proxy application traffic through the socks5 server",
		Long:  "Run a command in an unprivileged container that transparently proxies application traffic through the socks5 server",
		RunE: func(cmd *cobra.Command, args []string) error {
			return Try(func() {
				if c.opts.ContainerUID < 0 {
					ThrowFmt("uid is negative")
				}

				if c.opts.ContainerGID < 0 {
					ThrowFmt("gid is negative")
				}

				if len(c.opts.ForwardProxies) == 0 {
					ThrowFmt("forward proxies list is empty")
				}

				if c.opts.Quiet {
					log = setLogLevel(-1)
				} else {
					log = setLogLevel(c.opts.VerboseLevel)
				}

				log.Debug("forward", "proxies", c.opts.ForwardProxies)
				log.Debug("local_address_mappings", "mappings", c.opts.LocalAddressMappings)

				forwardProxies := parseProxyURLs(c.opts.ForwardProxies)
				nat := parseAddressMapper(c.opts.LocalAddressMappings)

				parentFd, childFd := newUnixSocketPair()
				defer unix.Close(parentFd)
				defer unix.Close(childFd)

				privileged := os.Geteuid() == 0

				proc := exec.Command("/proc/self/exe", append([]string{"runc",
					"--unix-fd", strconv.Itoa(childFd), fmt.Sprintf("--privileged=%t", privileged),
					"--uid", strconv.Itoa(c.opts.ContainerUID), "--gid", strconv.Itoa(c.opts.ContainerGID), "--"}, args...)...)

				proc.Stdin = os.Stdin
				proc.Stdout = os.Stdout
				proc.Stderr = os.Stderr

				if privileged {
					proc.SysProcAttr = &syscall.SysProcAttr{
						Cloneflags: syscall.CLONE_NEWUTS | syscall.CLONE_NEWNET | syscall.CLONE_NEWNS,
					}
				} else {
					proc.SysProcAttr = &syscall.SysProcAttr{
						Cloneflags: syscall.CLONE_NEWUTS | syscall.CLONE_NEWNET | syscall.CLONE_NEWNS | syscall.CLONE_NEWUSER,
						Credential: &syscall.Credential{Uid: 0, Gid: uint32(c.opts.ContainerGID)},
						UidMappings: []syscall.SysProcIDMap{
							{ContainerID: 0, HostID: os.Geteuid(), Size: 1},
						},
						GidMappings: []syscall.SysProcIDMap{
							{ContainerID: c.opts.ContainerGID, HostID: os.Getegid(), Size: 1},
						},
					}
				}

				Throw(proc.Start())

				parentConn := newParentUnixSocketConn(parentFd)

				tunFd := parentConn.ReceiveFd()
				defer unix.Close(tunFd)

				tunMTU := parentConn.ReceiveMTU()

				log.Debug("got tun device", "fd", tunFd)
				log.Debug("mtu", "mtu", tunMTU)

				dconn := NewDirectConnector()

				socksTCPConn := dconn
				socksTCPConns := make([]Connector, 0, len(c.opts.ForwardProxies)+1)
				socksTCPConns = append(socksTCPConns, dconn)

				for _, proxyAddr := range forwardProxies {
					socksTCPConn = NewSOCKS5Connector(socksTCPConn, proxyAddr)
					socksTCPConns = append(socksTCPConns, socksTCPConn)
				}

				socksUDPConn := dconn

				for i, proxyAddr := range forwardProxies {
					socksUDPConn = NewSOCKS5UDPConnector(log, socksTCPConns[i], socksUDPConn, proxyAddr)
				}

				socksTCPConn = NewLocalForwardingConnector(dconn, socksTCPConn, nat)
				socksUDPConn = NewLocalForwardingConnector(dconn, socksUDPConn, nat)

				stack := NewNetworkStack(log, tunFd, tunMTU, tunNetworkAddr, socksTCPConn, socksUDPConn, NewTransporter(log))
				defer stack.Close()

				parentConn.SendACK()

				Throw(proc.Wait())
			}).AsError()
		},
	}

	c.opts.initCliFlags(cmd)

	c.cmd = cmd

	return c
}

type runCmd struct {
	cmd  *cobra.Command
	opts runCmdOpts
}

type runCmdOpts struct {
	ForwardProxies       []string
	LocalAddressMappings []string
	VerboseLevel         int
	Quiet                bool
	ContainerUID         int
	ContainerGID         int
}

func (o *runCmdOpts) initCliFlags(cmd *cobra.Command) {
	cmd.Flags().StringArrayVarP(&o.ForwardProxies, "forward", "F", nil, "set socks5 proxy address to forward TCP/UDP packets")
	forwardFlag := cmd.Flags().Lookup("forward")
	forwardFlag.Value = &renamedTypeFlagValue{Value: forwardFlag.Value, name: "address", hideDefault: true}

	cmd.Flags().CountVarP(&o.VerboseLevel, "verbose", "v", "log verbose level")
	verboseFlag := cmd.Flags().Lookup("verbose")
	verboseFlag.Value = &renamedTypeFlagValue{Value: verboseFlag.Value}

	cmd.Flags().BoolVarP(&o.Quiet, "quiet", "q", false, "suppress all log output")

	cmd.Flags().StringArrayVarP(&o.LocalAddressMappings, "local", "L", nil, "specifies that connections to the target host and TCP/UDP port are to be directly forwarded to the given host and port")
	localFlag := cmd.Flags().Lookup("local")
	localFlag.Value = &renamedTypeFlagValue{Value: localFlag.Value, name: "[target_host:]port:host:hostport[/proto]", hideDefault: true}

	cmd.Flags().IntVar(&o.ContainerUID, "uid", os.Geteuid(), "set uid of container process")
	cmd.Flags().IntVar(&o.ContainerGID, "gid", os.Getegid(), "set gid of container process")
}

func newUnixSocketPair() (parentFd, childFd int) {
	fds := Throw2(unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0))
	parentFd = fds[0]
	childFd = fds[1]

	// set clo_exec flag on parent file descriptor
	_, err := unix.FcntlInt(uintptr(parentFd), unix.F_SETFD, unix.FD_CLOEXEC)

	if err != nil {
		err = multierr.Append(err, unix.Close(parentFd))
		err = multierr.Append(err, unix.Close(childFd))

		Throw(err)
	}

	return
}

type parentUnixSocketConn struct {
	socketFd   int
	socketFile *os.File
}

func newParentUnixSocketConn(socketFd int) *parentUnixSocketConn {
	return &parentUnixSocketConn{
		socketFd:   socketFd,
		socketFile: os.NewFile(uintptr(socketFd), "parentPipe"),
	}
}

func (c *parentUnixSocketConn) Close() error {
	return unix.Close(c.socketFd)
}

func (c *parentUnixSocketConn) ReceiveFd() int {
	// receive socket control message
	b := make([]byte, unix.CmsgSpace(4))
	_, _, _, _, err := unix.Recvmsg(c.socketFd, nil, b, 0)
	Throw(err)

	// parse socket control message
	cmsgs := Throw2(unix.ParseSocketControlMessage(b))
	tunFds := Throw2(unix.ParseUnixRights(&cmsgs[0]))

	if len(tunFds) == 0 {
		ThrowFmt("tun fds slice is empty")
	}

	return tunFds[0]
}

func (c *parentUnixSocketConn) ReceiveMTU() uint32 {
	var msg MTUMessage

	Throw(json.NewDecoder(c.socketFile).Decode(&msg))

	return msg.MTU
}

func (c *parentUnixSocketConn) SendACK() {
	Throw(json.NewEncoder(c.socketFile).Encode(&ACKMessage{ACK: true}))
}

type ACKMessage struct {
	ACK bool
}
