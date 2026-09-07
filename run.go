package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"errors"
	"log/slog"

	"golang.org/x/sys/unix"
)

func runRun(log *slog.Logger, args []string) {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)

	var forwardProxies stringArrayFlag
	var localMappings stringArrayFlag
	var bypassCIDRs stringArrayFlag
	var verboseLevel countFlag

	fs.Var(&forwardProxies, "F", "socks5 proxy address to forward TCP/UDP packets")
	fs.Var(&localMappings, "L", "local address mapping [target_host:]port:host:hostport[/proto]")
	fs.Var(&bypassCIDRs, "B", "bypass CIDR — destinations whose IP falls in this network go direct, not through SOCKS")
	fs.Var(&verboseLevel, "v", "log verbose level")

	dnsServer := fs.String("D", "", "upstream DNS address for the local resolver on 127.0.0.1:53 (IPv4-only unless -6)")
	ipv6 := fs.Bool("6", false, "enable IPv6 on the TUN; AAAA answers are kept only for addresses reachable via -B")
	nat64Prefix := fs.String("nat64", "", "NAT64 /96 prefix of the host (e.g. 64:ff9b::/96): bypassed IPv4 is dialed through it, synthesized IPv6 is unmapped")
	quiet := fs.Bool("q", false, "suppress all log output")
	uid := fs.Int("uid", os.Geteuid(), "set uid of container process")
	gid := fs.Int("gid", os.Getegid(), "set gid of container process")

	Throw(fs.Parse(args))

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
	log.Debug("bypass_cidrs", "cidrs", []string(bypassCIDRs))
	log.Debug("ipv6", "enabled", *ipv6, "nat64", *nat64Prefix)

	parsedProxies := parseProxyURLs(forwardProxies)
	nat := parseAddressMapper(localMappings)
	bypass := parseBypassNets(bypassCIDRs)
	dnsUpstream := parseUpstreamDNS(*dnsServer)
	nat64 := parseNAT64(*nat64Prefix)

	parentFd, childFd := newUnixSocketPair()
	defer unix.Close(parentFd)
	defer func() {
		if childFd >= 0 {
			_ = unix.Close(childFd)
		}
	}()

	privileged := isInitialUserNamespaceRoot()

	cmdArgs := fs.Args()
	proc := exec.Command("/proc/self/exe", append([]string{"runc",
		"-unix-fd", strconv.Itoa(childFd), fmt.Sprintf("-privileged=%t", privileged),
		fmt.Sprintf("-dns=%t", dnsUpstream != ""), fmt.Sprintf("-ipv6=%t", *ipv6),
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
	Throw(unix.Close(childFd))
	childFd = -1

	parentConn := newParentUnixSocketConn(parentFd)

	fds := parentConn.ReceiveFds()

	tunFd := fds[0]
	defer unix.Close(tunFd)

	dnsFd := -1

	if dnsUpstream != "" {
		if len(fds) < 2 {
			ThrowFmt("dns socket fd not received")
		}

		dnsFd = fds[1]
	}

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

	socksTCPConn = NewLocalForwardingConnector(dconn, socksTCPConn, nat, bypass, nat64)
	socksUDPConn = NewLocalForwardingConnector(dconn, socksUDPConn, nat, bypass, nat64)

	tunNetworkAddr6 := ""

	if *ipv6 {
		tunNetworkAddr6 = tunNetworkAddrV6
	}

	stack := NewNetworkStack(log, tunFd, tunMTU, tunNetworkAddr, tunNetworkAddr6, socksTCPConn, socksUDPConn, NewTransporter(log))
	defer stack.Close()

	if dnsFd >= 0 {
		log.Debug("starting local dns resolver", "upstream", dnsUpstream)
		startDNSResolver(log, dnsFd, dnsUpstream, &dnsPolicy{ipv6: *ipv6, allow: bypass, nat64: nat64})
	}

	parentConn.SendACK()

	Throw(proc.Wait())
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

func (c *parentUnixSocketConn) ReceiveFds() []int {
	// receive socket control message (room for several fds)
	b := make([]byte, unix.CmsgSpace(4*8))
	_, oobn, _, _, err := unix.Recvmsg(c.socketFd, nil, b, 0)
	Throw(err)

	if oobn == 0 {
		ThrowFmt("wirez child exited before sending network file descriptors")
	}

	// parse socket control message (only the bytes actually received)
	cmsgs := Throw2(unix.ParseSocketControlMessage(b[:oobn]))
	fds := Throw2(unix.ParseUnixRights(&cmsgs[0]))

	if len(fds) == 0 {
		ThrowFmt("received fds slice is empty")
	}

	return fds
}

func isInitialUserNamespaceRoot() bool {
	if os.Geteuid() != 0 {
		return false
	}

	data, err := os.ReadFile("/proc/self/uid_map")

	if err != nil {
		return false
	}

	fields := strings.Fields(string(data))

	if len(fields) < 3 {
		return false
	}

	containerID, err1 := strconv.ParseUint(fields[0], 10, 64)
	hostID, err2 := strconv.ParseUint(fields[1], 10, 64)
	size, err3 := strconv.ParseUint(fields[2], 10, 64)

	return err1 == nil && err2 == nil && err3 == nil &&
		containerID == 0 && hostID == 0 && size > 1
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
