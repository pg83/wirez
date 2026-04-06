package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"

	"errors"
	"log/slog"

	"golang.org/x/sys/unix"
)

func runRun(log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	var forwardProxies stringArrayFlag
	var localMappings stringArrayFlag
	var verboseLevel countFlag
	fs.Var(&forwardProxies, "F", "socks5 proxy address to forward TCP/UDP packets")
	fs.Var(&localMappings, "L", "local address mapping [target_host:]port:host:hostport[/proto]")
	fs.Var(&verboseLevel, "v", "log verbose level")
	quiet := fs.Bool("q", false, "suppress all log output")
	uid := fs.Int("uid", os.Geteuid(), "set uid of container process")
	gid := fs.Int("gid", os.Getegid(), "set gid of container process")

	if err := fs.Parse(args); err != nil {
		return err
	}

	return Try(func() {
		if *uid < 0 {
			ThrowFmt("uid is negative")
		}

		if *gid < 0 {
			ThrowFmt("gid is negative")
		}

		if len(forwardProxies) == 0 {
			ThrowFmt("forward proxies list is empty")
		}

		if *quiet {
			log = setLogLevel(-1)
		} else {
			log = setLogLevel(int(verboseLevel))
		}

		log.Debug("forward", "proxies", []string(forwardProxies))
		log.Debug("local_address_mappings", "mappings", []string(localMappings))

		parsedProxies := parseProxyURLs(forwardProxies)
		nat := parseAddressMapper(localMappings)

		parentFd, childFd := newUnixSocketPair()
		defer unix.Close(parentFd)
		defer unix.Close(childFd)

		privileged := os.Geteuid() == 0

		cmdArgs := fs.Args()
		proc := exec.Command("/proc/self/exe", append([]string{"runc",
			"-unix-fd", strconv.Itoa(childFd), fmt.Sprintf("-privileged=%t", privileged),
			"-uid", strconv.Itoa(*uid), "-gid", strconv.Itoa(*gid), "--"}, cmdArgs...)...)

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
				Credential: &syscall.Credential{Uid: 0, Gid: uint32(*gid)},
				UidMappings: []syscall.SysProcIDMap{
					{ContainerID: 0, HostID: os.Geteuid(), Size: 1},
				},
				GidMappings: []syscall.SysProcIDMap{
					{ContainerID: *gid, HostID: os.Getegid(), Size: 1},
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
		socksTCPConns := make([]Connector, 0, len(forwardProxies)+1)
		socksTCPConns = append(socksTCPConns, dconn)

		for _, proxyAddr := range parsedProxies {
			socksTCPConn = NewSOCKS5Connector(socksTCPConn, proxyAddr)
			socksTCPConns = append(socksTCPConns, socksTCPConn)
		}

		socksUDPConn := dconn

		for i, proxyAddr := range parsedProxies {
			socksUDPConn = NewSOCKS5UDPConnector(log, socksTCPConns[i], socksUDPConn, proxyAddr)
		}

		socksTCPConn = NewLocalForwardingConnector(dconn, socksTCPConn, nat)
		socksUDPConn = NewLocalForwardingConnector(dconn, socksUDPConn, nat)

		stack := NewNetworkStack(log, tunFd, tunMTU, tunNetworkAddr, socksTCPConn, socksUDPConn, NewTransporter(log))
		defer stack.Close()

		parentConn.SendACK()

		Throw(proc.Wait())
	}).AsError()
}

func newUnixSocketPair() (parentFd, childFd int) {
	fds := Throw2(unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0))

	parentFd = fds[0]
	childFd = fds[1]

	// set clo_exec flag on parent file descriptor
	_, err := unix.FcntlInt(uintptr(parentFd), unix.F_SETFD, unix.FD_CLOEXEC)

	if err != nil {
		err = errors.Join(err, unix.Close(parentFd))
		err = errors.Join(err, unix.Close(childFd))

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
