//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/link/tun"
)

const (
	loDevice       = "lo"
	tunDevice      = "tun0"
	tunNetworkAddr = "10.1.1.1/24"
)

func newRunContainerCmd() *runContainerCmd {
	c := &runContainerCmd{}

	cmd := &cobra.Command{
		Use:     "runc [flags] command",
		Example: "runc --hostname=wirez --unix-fd=10 bash",
		Short:   "Internal command to run a new process inside an isolated container",
		Hidden:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return Try(func() {
				Throw(syscall.Sethostname([]byte(c.opts.Hostname)))
				childConn := newChildUnixSocketConn(c.opts.PipeFd)
				defer childConn.Close()
				tunFd := Throw2(tun.Open(tunDevice))
				defer unix.Close(tunFd)

				childConn.SendFd(tunFd)

				link := Throw2(netlink.LinkByName(tunDevice))

				childConn.SendMTU(uint32(link.Attrs().MTU))

				// wait for starting network stack
				childConn.ReceiveACK()

				setupIPNetwork()
				setupResolvConf()

				proc := exec.Command(args[0], args[1:]...)
				proc.Stdin = os.Stdin
				proc.Stdout = os.Stdout
				proc.Stderr = os.Stderr

				if c.opts.Privileged {
					proc.SysProcAttr = &syscall.SysProcAttr{
						Credential: &syscall.Credential{Uid: uint32(c.opts.ContainerUID), Gid: uint32(c.opts.ContainerGID)},
					}
				} else if c.opts.ContainerUID != 0 {
					proc.SysProcAttr = &syscall.SysProcAttr{
						Cloneflags: syscall.CLONE_NEWUSER,
						Credential: &syscall.Credential{Uid: uint32(c.opts.ContainerUID), Gid: uint32(c.opts.ContainerGID)},
						UidMappings: []syscall.SysProcIDMap{
							{ContainerID: c.opts.ContainerUID, HostID: os.Geteuid(), Size: 1},
						},
						GidMappings: []syscall.SysProcIDMap{
							{ContainerID: c.opts.ContainerGID, HostID: os.Getegid(), Size: 1},
						},
					}
				}

				Throw(proc.Run())
			}).AsError()
		},
	}

	c.opts.initCliFlags(cmd)

	c.cmd = cmd

	return c
}

type runContainerCmd struct {
	cmd  *cobra.Command
	opts runContainerCmdOpts
}

type runContainerCmdOpts struct {
	Hostname     string
	PipeFd       int
	ContainerUID int
	ContainerGID int
	Privileged   bool
}

func (o *runContainerCmdOpts) initCliFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.Hostname, "hostname", "wirez", "set container hostname")
	cmd.Flags().IntVar(&o.PipeFd, "unix-fd", 0, "set unix pipe fd")
	cmd.Flags().IntVar(&o.ContainerUID, "uid", os.Geteuid(), "set uid of container process")
	cmd.Flags().IntVar(&o.ContainerGID, "gid", os.Getegid(), "set gid of container process")
	cmd.Flags().BoolVar(&o.Privileged, "privileged", false, "indicates if started with root privileges")
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

func (c *childUnixSocketConn) SendFd(fd int) {
	rights := unix.UnixRights(fd)
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
		Throw(errors.New("network stack initialization is not acknowledged"))
	}
}

type MTUMessage struct {
	MTU uint32 `json:"mtu"`
}

func setupIPNetwork() {
	lo := Throw2(netlink.LinkByName(loDevice))
	Throw(netlink.LinkSetUp(lo))
	tun0, tunAddr := setupIPAddress(tunDevice, tunNetworkAddr)
	Throw(netlink.RouteAdd(&netlink.Route{
		Gw:        tunAddr.IP,
		LinkIndex: tun0.Attrs().Index,
	}))
}

const resolvConfTmpDir = "/tmp/.wirez-resolv"

func setupResolvConf() {
	// Prevent mount propagation to the host.
	Throw(unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""))

	// Parse TUN IP and use next IP in subnet as nameserver,
	// because the TUN IP itself is a local address and packets to it
	// don't traverse the TUN device.
	ip, _ := Throw3(net.ParseCIDR(tunNetworkAddr))
	ip = ip.To4()
	ip[3]++

	// Write resolv.conf to a tmpfs so we don't touch the host filesystem.
	Throw(os.MkdirAll(resolvConfTmpDir, 0755))
	Throw(unix.Mount("tmpfs", resolvConfTmpDir, "tmpfs", 0, "size=4k"))

	tmpFile := resolvConfTmpDir + "/resolv.conf"

	Throw(os.WriteFile(tmpFile, []byte("nameserver "+ip.String()+"\n"), 0644))

	// Bind mount over /etc/resolv.conf.
	Throw(unix.Mount(tmpFile, "/etc/resolv.conf", "", unix.MS_BIND, ""))
}

func setupIPAddress(device, networkAddr string) (netlink.Link, *netlink.Addr) {
	dev := Throw2(netlink.LinkByName(device))
	Throw(netlink.LinkSetUp(dev))

	addr := Throw2(netlink.ParseAddr(networkAddr))
	Throw(netlink.AddrAdd(dev, addr))

	return dev, addr
}
