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
	"time"

	"log/slog"

	"golang.org/x/sys/unix"
)

// runFlags is the parsed command line of the outer wirez process.
type runFlags struct {
	forwardProxies stringArrayFlag
	localMappings  stringArrayFlag
	bypassCIDRs    stringArrayFlag
	dnsServers     stringArrayFlag
	verboseLevel   countFlag
	ipv6           bool
	nat64Prefix    string
	hostname       string
	connectTimeout time.Duration
	tcpTimeout     time.Duration
	udpTimeout     time.Duration
	quiet          bool
	uid            int
	gid            int
}

// newRunFlagSet declares every flag wirez accepts. usageText in root.go has
// to describe each of them; TestUsageMentionsEveryFlag keeps the two in sync.
func newRunFlagSet() (*flag.FlagSet, *runFlags) {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	f := &runFlags{}

	fs.Var(&f.forwardProxies, "F", "proxy to forward through: [socks5://]host:port or http://host:port (repeat to chain)")
	fs.Var(&f.localMappings, "L", "local address mapping [target_host:]port:host:hostport[/proto]")
	fs.Var(&f.bypassCIDRs, "B", "bypass CIDR — destinations whose IP falls in this network go direct, not through the proxy")
	fs.Var(&f.dnsServers, "D", "upstream DNS address for the local resolver on 127.0.0.1:53 (repeat for failover; IPv4-only unless -6)")
	fs.Var(&f.verboseLevel, "v", "log verbose level")
	fs.BoolVar(&f.ipv6, "6", false, "enable IPv6 on the TUN; AAAA answers are kept only for addresses reachable via -B")
	fs.StringVar(&f.nat64Prefix, "nat64", "", "NAT64 /96 prefix of the host (e.g. 64:ff9b::/96): bypassed IPv4 is dialed through it, synthesized IPv6 is unmapped")
	fs.StringVar(&f.hostname, "hostname", "wirez", "hostname inside the container")
	fs.DurationVar(&f.connectTimeout, "connect-timeout", connectTimeout, "timeout of a dial, proxy handshakes included")
	fs.DurationVar(&f.tcpTimeout, "tcp-timeout", 0, "idle timeout of TCP connections, 0 disables it")
	fs.DurationVar(&f.udpTimeout, "udp-timeout", udpIOTimeout, "idle timeout of UDP flows")
	fs.BoolVar(&f.quiet, "q", false, "suppress all log output")
	fs.IntVar(&f.uid, "uid", os.Geteuid(), "set uid of container process")
	fs.IntVar(&f.gid, "gid", os.Getegid(), "set gid of container process")

	return fs, f
}

func runRun(log *slog.Logger, args []string) {
	fs, f := newRunFlagSet()

	Throw(fs.Parse(args))

	if f.uid < 0 {
		ThrowFmt("uid is negative")
	}

	if f.gid < 0 {
		ThrowFmt("gid is negative")
	}

	if len(f.forwardProxies) == 0 {
		ThrowFmt("forward proxies list is empty")
	}

	if f.connectTimeout <= 0 || f.udpTimeout <= 0 || f.tcpTimeout < 0 {
		ThrowFmt("timeouts must be positive (-tcp-timeout may be 0)")
	}

	if f.quiet {
		log = setLogLevel(-1)
	} else {
		log = setLogLevel(int(f.verboseLevel))
	}

	log.Debug("forward", "proxies", []string(f.forwardProxies))
	log.Debug("local_address_mappings", "mappings", []string(f.localMappings))
	log.Debug("bypass_cidrs", "cidrs", []string(f.bypassCIDRs))
	log.Debug("dns", "upstreams", []string(f.dnsServers))
	log.Debug("ipv6", "enabled", f.ipv6, "nat64", f.nat64Prefix)

	parsedProxies := parseProxyURLs(f.forwardProxies)
	nat := parseAddressMapper(f.localMappings)
	bypass := parseBypassNets(f.bypassCIDRs)
	dnsUpstreams := parseUpstreamDNSList(f.dnsServers)
	nat64 := parseNAT64(f.nat64Prefix)
	useDNS := len(dnsUpstreams) > 0

	parentConn, childFile := newControlSocket()
	defer parentConn.Close()
	defer childFile.Close()

	privileged := isInitialUserNamespaceRoot()

	cmdArgs := fs.Args()
	proc := exec.Command("/proc/self/exe", append([]string{"runc",
		"-unix-fd", "3", fmt.Sprintf("-privileged=%t", privileged),
		fmt.Sprintf("-dns=%t", useDNS), fmt.Sprintf("-ipv6=%t", f.ipv6), "-hostname", f.hostname,
		"-uid", strconv.Itoa(f.uid), "-gid", strconv.Itoa(f.gid), "--"}, cmdArgs...)...)
	proc.Stdin = os.Stdin
	proc.Stdout = os.Stdout
	proc.Stderr = os.Stderr
	// the child's end of the control socket, as descriptor 3
	proc.ExtraFiles = []*os.File{childFile}

	// The container is useless without this process driving its TUN, so it
	// must not outlive it.
	if privileged {
		proc.SysProcAttr = &syscall.SysProcAttr{
			Cloneflags: syscall.CLONE_NEWUTS | syscall.CLONE_NEWNET | syscall.CLONE_NEWNS,
			Pdeathsig:  syscall.SIGKILL,
		}
	} else {
		proc.SysProcAttr = &syscall.SysProcAttr{
			Cloneflags: syscall.CLONE_NEWUTS | syscall.CLONE_NEWNET | syscall.CLONE_NEWNS | syscall.CLONE_NEWUSER,
			Pdeathsig:  syscall.SIGKILL,
			Credential: &syscall.Credential{Uid: 0, Gid: uint32(f.gid)},
			UidMappings: []syscall.SysProcIDMap{
				{ContainerID: 0, HostID: os.Geteuid(), Size: 1},
			},
			GidMappings: []syscall.SysProcIDMap{
				{ContainerID: f.gid, HostID: os.Getegid(), Size: 1},
			},
		}
	}

	Throw(proc.Start())
	// only the child holds its end now, so its exit shows up as EOF
	Throw(childFile.Close())

	wantFds := 1

	if useDNS {
		wantFds = 3
	}

	fds := parentConn.ReceiveFds(wantFds)

	tunFd := fds[0]
	defer unix.Close(tunFd)

	dnsUDPFd, dnsTCPFd := -1, -1

	if useDNS {
		dnsUDPFd, dnsTCPFd = fds[1], fds[2]
	}

	tunMTU := parentConn.ReceiveMTU()

	log.Debug("got tun device", "fd", tunFd)
	log.Debug("mtu", "mtu", tunMTU)

	socksTCPConn, socksUDPConn := buildProxyChain(log, parsedProxies)

	tunNetworks := []string{tunNetworkAddr}

	if f.ipv6 {
		tunNetworks = append(tunNetworks, tunNetworkAddrV6)
	}

	tunNets := parseBypassNets(tunNetworks)
	dconn := NewDirectConnector()
	socksTCPConn = NewLocalForwardingConnector(dconn, socksTCPConn, nat, bypass, tunNets, nat64)
	socksUDPConn = NewLocalForwardingConnector(dconn, socksUDPConn, nat, bypass, tunNets, nat64)

	stack := NewNetworkStack(NetworkStackOptions{
		Log:            log,
		Link:           newTUNEndpoint(tunFd, tunMTU),
		Networks:       tunNetworks,
		TCP:            socksTCPConn,
		UDP:            socksUDPConn,
		Transporter:    NewTransporter(log),
		ConnectTimeout: f.connectTimeout,
		TCPIdleTimeout: f.tcpTimeout,
		UDPIdleTimeout: f.udpTimeout,
	})
	defer stack.Close()

	if useDNS {
		log.Debug("starting local dns resolver", "upstreams", dnsUpstreams)
		startDNSResolver(log, dnsUDPFd, dnsTCPFd, newDNSUpstreams(dnsUpstreams), &dnsPolicy{ipv6: f.ipv6, allow: bypass, nat64: nat64})
	}

	parentConn.SendACK()

	Throw(proc.Wait())
}

// buildProxyChain stacks the -F hops: each hop's control connection is dialed
// through the previous one. UDP rides on SOCKS5 UDP ASSOCIATE and is refused
// as soon as an HTTP hop, which has no UDP, is in the chain.
func buildProxyChain(log *slog.Logger, proxies []*ProxyAddr) (tcpConn, udpConn Connector) {
	direct := NewDirectConnector()
	tcpConn = direct

	tcpHops := make([]Connector, 0, len(proxies)+1)
	tcpHops = append(tcpHops, direct)
	httpHop := false

	for _, proxy := range proxies {
		if proxy.Scheme == "http" {
			tcpConn = NewHTTPConnector(tcpConn, proxy)
			httpHop = true
		} else {
			tcpConn = NewSOCKS5Connector(tcpConn, proxy)
		}

		tcpHops = append(tcpHops, tcpConn)
	}

	if httpHop {
		return tcpConn, &unsupportedConnector{reason: "udp is not supported through an HTTP proxy"}
	}

	udpConn = direct

	for i, proxy := range proxies {
		udpConn = NewSOCKS5UDPConnector(log, tcpHops[i], udpConn, proxy)
	}

	return tcpConn, udpConn
}

// newControlSocket makes the socket pair the two halves talk over. Both ends
// are close-on-exec: the container gets its end as an extra file, nothing
// else inherits either.
func newControlSocket() (*parentUnixSocketConn, *os.File) {
	fds := Throw2(unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0))

	return newParentUnixSocketConn(fds[0]), os.NewFile(uintptr(fds[1]), "childPipe")
}

// parentUnixSocketConn is the parent's end of the control socket. The
// *os.File owns the descriptor: a raw unix.Close next to it would close the
// number twice, the second time from the File's finalizer, when the number
// may already belong to something else.
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
	return c.socketFile.Close()
}

// ReceiveFds takes the descriptors the container sends over the control
// socket; a container that died first sends nothing.
func (c *parentUnixSocketConn) ReceiveFds(want int) []int {
	b := make([]byte, unix.CmsgSpace(4*want))
	_, oobn, _, _, err := unix.Recvmsg(c.socketFd, nil, b, 0)
	Throw(err)

	if oobn == 0 {
		ThrowFmt("wirez child exited before sending network file descriptors")
	}

	cmsgs := Throw2(unix.ParseSocketControlMessage(b[:oobn]))
	fds := Throw2(unix.ParseUnixRights(&cmsgs[0]))

	if len(fds) != want {
		ThrowFmt("received %d network file descriptors, want %d", len(fds), want)
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
