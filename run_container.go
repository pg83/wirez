package main

import (
	"encoding/json"
	"flag"
	"net"
	"os"
	"os/exec"
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

	childConn := newChildUnixSocketConn(*pipeFd)
	defer childConn.Close()

	tunFd := Throw2(tun.Open(tunDevice))
	defer unix.Close(tunFd)

	fds := []int{tunFd}

	if *dns {
		setupLoopback()

		dnsFd := createResolverSocket()
		defer unix.Close(dnsFd)

		fds = append(fds, dnsFd)
	}

	childConn.SendFds(fds...)

	link := Throw2(netlink.LinkByName(tunDevice))
	childConn.SendMTU(uint32(link.Attrs().MTU))

	// wait for starting network stack
	childConn.ReceiveACK()

	setupIPNetwork(*ipv6)
	setupResolvConf(*dns)
	setupHosts(*hostname)

	cmdArgs := fs.Args()
	proc := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	proc.Stdin = os.Stdin
	proc.Stdout = os.Stdout
	proc.Stderr = os.Stderr

	if *privileged {
		proc.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{Uid: uint32(*uid), Gid: uint32(*gid)},
		}
	} else if *uid != 0 {
		proc.SysProcAttr = &syscall.SysProcAttr{
			Cloneflags: syscall.CLONE_NEWUSER,
			Credential: &syscall.Credential{Uid: uint32(*uid), Gid: uint32(*gid)},
			UidMappings: []syscall.SysProcIDMap{
				{ContainerID: *uid, HostID: os.Geteuid(), Size: 1},
			},
			GidMappings: []syscall.SysProcIDMap{
				{ContainerID: *gid, HostID: os.Getegid(), Size: 1},
			},
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

func createResolverSocket() int {
	fd := Throw2(unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0))

	Throw(unix.Bind(fd, &unix.SockaddrInet4{Port: 53, Addr: [4]byte{127, 0, 0, 1}}))

	return fd
}

func setupIPNetwork(ipv6 bool) {
	setupLoopback()

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

func setupResolvConf(dns bool) {
	// Prevent mount propagation to the host.
	Throw(unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""))

	// With a local resolver, point at 127.0.0.1. Otherwise use the next IP in
	// the TUN subnet as nameserver, because the TUN IP itself is a local
	// address and packets to it don't traverse the TUN device.
	nameserver := "127.0.0.1"

	if !dns {
		ip, _ := Throw3(net.ParseCIDR(tunNetworkAddr))
		ip = ip.To4()
		ip[3]++
		nameserver = ip.String()
	}

	// Write resolv.conf to a tmpfs so we don't touch the host filesystem.
	tmpDir := Throw2(os.MkdirTemp(os.TempDir(), "wirez-resolv-"))
	Throw(unix.Mount("tmpfs", tmpDir, "tmpfs", 0, "size=4k"))

	tmpFile := tmpDir + "/resolv.conf"

	Throw(os.WriteFile(tmpFile, []byte("nameserver "+nameserver+"\n"), 0644))
	// Bind mount over /etc/resolv.conf.
	Throw(unix.Mount(tmpFile, "/etc/resolv.conf", "", unix.MS_BIND, ""))
}

func setupHosts(hostname string) {
	ip, _ := Throw3(net.ParseCIDR(tunNetworkAddr))
	ip = ip.To4()
	ip[3]++

	// localhost resolves to the loopback addresses first, so that programs
	// binding "localhost" get an address that exists inside the container
	// (127.0.0.1/::1); the TUN peer address comes last: connections to it
	// traverse the TUN and can be redirected with -L, and clients that
	// iterate over getaddrinfo() results reach it after the loopback ones
	// are refused. The container hostname resolves to loopback so that
	// FQDN lookups (getaddrinfo(hostname, AI_CANONNAME)) succeed.
	hosts := "127.0.0.1 localhost\n::1 localhost\n" + ip.String() + " localhost\n" +
		"127.0.0.1 " + hostname + " " + hostname + ".localdomain\n" +
		"::1 " + hostname + " " + hostname + ".localdomain\n"

	tmpDir := Throw2(os.MkdirTemp(os.TempDir(), "wirez-hosts-"))
	Throw(unix.Mount("tmpfs", tmpDir, "tmpfs", 0, "size=4k"))

	tmpFile := tmpDir + "/hosts"

	Throw(os.WriteFile(tmpFile, []byte(hosts), 0644))
	Throw(unix.Mount(tmpFile, "/etc/hosts", "", unix.MS_BIND, ""))
}

func setupIPAddress(device, networkAddr string) (netlink.Link, *netlink.Addr) {
	dev := Throw2(netlink.LinkByName(device))
	Throw(netlink.LinkSetUp(dev))

	addr := Throw2(netlink.ParseAddr(networkAddr))
	Throw(netlink.AddrAdd(dev, addr))

	return dev, addr
}
