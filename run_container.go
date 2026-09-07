package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/link/tun"
)

const (
	loDevice       = "lo"
	tunDevice      = "tun0"
	tunNetworkAddr = "10.1.1.1/24"
	// tunNetworkAddrV6 only has to be routable inside the container, but it
	// must not be a ULA: with a ULA source RFC 6724 (getaddrinfo ordering)
	// prefers IPv4 destinations over global IPv6 ones, which defeats the
	// point of -6. The documentation prefix has the plain "global" label.
	tunNetworkAddrV6 = "2001:db8:1:1::1/64"
)

func runContainer(args []string) {
	fs := flag.NewFlagSet("runc", flag.ContinueOnError)
	hostname := fs.String("hostname", "wirez", "set container hostname")
	pipeFd := fs.Int("unix-fd", 0, "set unix pipe fd")
	uid := fs.Int("uid", os.Geteuid(), "set uid of container process")
	gid := fs.Int("gid", os.Getegid(), "set gid of container process")
	privileged := fs.Bool("privileged", false, "indicates if started with root privileges")
	dns := fs.Bool("dns", false, "run local DNS resolver on 127.0.0.1:53")
	ipv6 := fs.Bool("ipv6", false, "configure IPv6 on the TUN device")

	Throw(fs.Parse(args))
	Throw(syscall.Sethostname([]byte(*hostname)))

	// Neither the control socket nor the network descriptors below belong to
	// the application that is exec'd at the end.
	unix.CloseOnExec(*pipeFd)

	childConn := newChildUnixSocketConn(*pipeFd)
	defer childConn.Close()

	tunFd := Throw2(tun.Open(tunDevice))
	defer unix.Close(tunFd)
	unix.CloseOnExec(tunFd)

	fds := []int{tunFd}

	if *dns {
		setupLoopback()

		udpFd, tcpFd := createResolverSockets()
		defer unix.Close(udpFd)
		defer unix.Close(tcpFd)

		fds = append(fds, udpFd, tcpFd)
	}

	childConn.SendFds(fds...)

	link := Throw2(netlink.LinkByName(tunDevice))
	childConn.SendMTU(uint32(link.Attrs().MTU))

	// wait for starting network stack
	childConn.ReceiveACK()

	setupIPNetwork(*ipv6, *gid)

	makeMountsPrivate()
	bindMountFile("/etc/resolv.conf", resolvConfContent(*dns, readHostFile("/etc/resolv.conf")))
	bindMountFile("/etc/hosts", hostsContent(*hostname, readHostFile("/etc/hosts")))

	cmdArgs := fs.Args()
	proc := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	proc.Stdin = os.Stdin
	proc.Stdout = os.Stdout
	proc.Stderr = os.Stderr

	// Without this process the container has no network, so the application
	// must not outlive it.
	proc.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}

	if *privileged {
		proc.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(*uid), Gid: uint32(*gid)}
	} else if *uid != 0 {
		proc.SysProcAttr.Cloneflags = syscall.CLONE_NEWUSER
		proc.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(*uid), Gid: uint32(*gid)}
		proc.SysProcAttr.UidMappings = []syscall.SysProcIDMap{
			{ContainerID: *uid, HostID: os.Geteuid(), Size: 1},
		}
		proc.SysProcAttr.GidMappings = []syscall.SysProcIDMap{
			{ContainerID: *gid, HostID: os.Getegid(), Size: 1},
		}
	}

	Throw(proc.Run())
}

type childUnixSocketConn struct {
	socketFd   int
	socketFile *os.File
}

func newChildUnixSocketConn(socketFd int) *childUnixSocketConn {
	return &childUnixSocketConn{
		socketFd:   socketFd,
		socketFile: os.NewFile(uintptr(socketFd), "childPipe"),
	}
}

func (c *childUnixSocketConn) Close() error {
	return unix.Close(c.socketFd)
}

func (c *childUnixSocketConn) SendFds(fds ...int) {
	rights := unix.UnixRights(fds...)

	Throw(unix.Sendmsg(c.socketFd, nil, rights, nil, 0))
}

func (c *childUnixSocketConn) SendMTU(mtu uint32) {
	data := Throw2(json.Marshal(&MTUMessage{MTU: mtu}))

	Throw2(c.socketFile.Write(data))
}

func (c *childUnixSocketConn) ReceiveACK() {
	var msg ACKMessage

	Throw(json.NewDecoder(c.socketFile).Decode(&msg))

	if !msg.ACK {
		ThrowFmt("network stack initialization is not acknowledged")
	}
}

type MTUMessage struct {
	MTU uint32 `json:"mtu"`
}

func setupLoopback() {
	lo := Throw2(netlink.LinkByName(loDevice))

	// Ensure 127.0.0.1 is present so a resolver can bind 127.0.0.1:53.
	if addr, err := netlink.ParseAddr("127.0.0.1/8"); err == nil {
		_ = netlink.AddrAdd(lo, addr)
	}

	Throw(netlink.LinkSetUp(lo))
}

// createResolverSockets binds the resolver's UDP socket and TCP listener to
// 127.0.0.1:53 inside the container; both are served from the host netns.
func createResolverSockets() (udpFd, tcpFd int) {
	addr := &unix.SockaddrInet4{Port: 53, Addr: [4]byte{127, 0, 0, 1}}

	udpFd = Throw2(unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0))
	Throw(unix.Bind(udpFd, addr))

	tcpFd = Throw2(unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0))
	Throw(unix.SetsockoptInt(tcpFd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1))
	Throw(unix.Bind(tcpFd, addr))
	Throw(unix.Listen(tcpFd, unix.SOMAXCONN))

	return udpFd, tcpFd
}

func setupIPNetwork(ipv6 bool, gid int) {
	setupLoopback()
	allowPing(gid)

	tun0, tunAddr := setupIPAddress(tunDevice, tunNetworkAddr)

	Throw(netlink.RouteAdd(&netlink.Route{
		Gw:        tunAddr.IP,
		LinkIndex: tun0.Attrs().Index,
	}))

	if !ipv6 {
		return
	}

	// A TUN device does neighbor discovery for nobody, so the address must
	// skip DAD and the default route is a plain device route.
	addr := Throw2(netlink.ParseAddr(tunNetworkAddrV6))
	addr.Flags = unix.IFA_F_NODAD
	Throw(netlink.AddrAdd(tun0, addr))

	Throw(netlink.RouteAdd(&netlink.Route{
		Dst:       &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
		LinkIndex: tun0.Attrs().Index,
	}))
}

// allowPing lets the application open ICMP echo sockets without CAP_NET_RAW;
// wirez answers the echoes itself. The range is spelled in the gid space of
// the user namespace owning the netns, where only the container gid exists.
// Best effort: without it only ping is missing.
func allowPing(gid int) {
	_ = os.WriteFile("/proc/sys/net/ipv4/ping_group_range", []byte(fmt.Sprintf("%d %d\n", gid, gid)), 0644)
}

// makeMountsPrivate stops the bind mounts made by bindMountFile from
// propagating to the host.
func makeMountsPrivate() {
	Throw(unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""))
}

// bindMountFile shadows target with a file of the given content that lives
// on a tmpfs private to the container, so the host filesystem is never
// touched. Requires makeMountsPrivate to have been called first.
func bindMountFile(target, content string) {
	// The staging directory is created on the host filesystem, so it is
	// removed again once the bind mount holds the file on its own.
	tmpDir := Throw2(os.MkdirTemp(os.TempDir(), "wirez-"))
	Throw(unix.Mount("tmpfs", tmpDir, "tmpfs", 0, "size=4k"))

	tmpFile := filepath.Join(tmpDir, filepath.Base(target))
	Throw(os.WriteFile(tmpFile, []byte(content), 0644))
	Throw(unix.Mount(tmpFile, target, "", unix.MS_BIND, ""))

	Throw(unix.Unmount(tmpDir, unix.MNT_DETACH))
	Throw(os.Remove(tmpDir))
}

// readHostFile returns the host's version of a file, or nothing when it
// cannot be read.
func readHostFile(path string) string {
	data, err := os.ReadFile(path)

	if err != nil {
		return ""
	}

	return string(data)
}

// tunPeerAddr is the address right after the TUN address in its subnet. The
// TUN address itself is local and packets to it never traverse the device;
// this one is reached through the TUN and therefore through wirez.
func tunPeerAddr() net.IP {
	ip, _ := Throw3(net.ParseCIDR(tunNetworkAddr))
	ip = ip.To4()
	ip[3]++

	return ip
}

// resolvConfContent points the container at the local resolver when one is
// running and at the TUN peer address otherwise, so DNS goes through wirez.
// The host's search list and options are kept so that short names resolve
// the same way inside.
func resolvConfContent(dns bool, hostResolv string) string {
	nameserver := "127.0.0.1"

	if !dns {
		nameserver = tunPeerAddr().String()
	}

	var b strings.Builder

	b.WriteString("nameserver " + nameserver + "\n")

	for _, line := range strings.Split(hostResolv, "\n") {
		fields := strings.Fields(line)

		if len(fields) == 0 {
			continue
		}

		switch fields[0] {
		case "search", "domain", "options", "sortlist":
			b.WriteString(strings.Join(fields, " ") + "\n")
		}
	}

	return b.String()
}

// hostsContent keeps the host's entries and appends wirez's own: localhost on
// the loopback addresses, so programs binding "localhost" get an address that
// exists inside the container, and on the TUN peer address last, where -L can
// redirect it (without a mapping the connection is refused). The container
// hostname resolves to loopback so that FQDN lookups (getaddrinfo(hostname,
// AI_CANONNAME)) succeed.
func hostsContent(hostname, hostHosts string) string {
	fqdn := hostname + " " + hostname + ".localdomain"
	own := "127.0.0.1 localhost\n" +
		"::1 localhost\n" +
		tunPeerAddr().String() + " localhost\n" +
		"127.0.0.1 " + fqdn + "\n" +
		"::1 " + fqdn + "\n"

	hostHosts = strings.TrimRight(hostHosts, "\n")

	if hostHosts == "" {
		return own
	}

	return hostHosts + "\n" + own
}

func setupIPAddress(device, networkAddr string) (netlink.Link, *netlink.Addr) {
	dev := Throw2(netlink.LinkByName(device))
	Throw(netlink.LinkSetUp(dev))

	addr := Throw2(netlink.ParseAddr(networkAddr))
	Throw(netlink.AddrAdd(dev, addr))

	return dev, addr
}
