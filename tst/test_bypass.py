"""-B networks go direct; everything else goes through the proxy. The test
runs in its own network namespace where addresses from the bypassed networks
sit on loopback, so servers bound to them play the LAN."""

import unittest

import lib

lib.reexec_in_netns(setup=[
    ["route", "add", "local", "198.51.100.0/24", "dev", "lo"],
    ["-6", "addr", "add", "2001:db8:b::7/128", "dev", "lo"],
])


class BypassTest(lib.ContainerTest):
    def test_bypass_network_goes_direct(self):
        echo = lib.EchoServer(host="198.51.100.7")
        proxy = lib.Socks5Server()
        flags = ["-F", proxy.addr, "-B", "198.51.100.0/24"]
        self.assertEqual(lib.in_container(flags, "tcp", echo.addr), "echo:hello")
        self.assertEqual(proxy.connects, [])

    def test_bypass_udp_goes_direct(self):
        echo = lib.UdpEchoServer(host="198.51.100.7")
        proxy = lib.Socks5Server()
        flags = ["-F", proxy.addr, "-B", "198.51.100.0/24"]
        self.assertEqual(lib.in_container(flags, "udp", echo.addr), "ping?")
        self.assertEqual(proxy.associations, 0)

    def test_ipv6_bypass_network_goes_direct(self):
        echo = lib.EchoServer(host="2001:db8:b::7")
        proxy = lib.Socks5Server()
        flags = ["-F", proxy.addr, "-6", "-B", "2001:db8:b::/48"]
        self.assertEqual(lib.in_container(flags, "tcp", echo.addr), "echo:hello")
        self.assertEqual(proxy.connects, [])

    def test_destinations_outside_bypass_use_the_proxy(self):
        echo = lib.EchoServer()
        proxy = lib.Socks5Server(backend=echo.addr)
        flags = ["-F", proxy.addr, "-B", "198.51.100.0/24"]
        self.assertEqual(lib.in_container(flags, "tcp", "192.0.2.1:8080"), "echo:hello")
        self.assertEqual(proxy.connects, ["192.0.2.1:8080"])

    def test_tun_subnet_is_refused_even_inside_a_bypass_network(self):
        proxy = lib.Socks5Server()
        flags = ["-F", proxy.addr, "-B", "10.0.0.0/8"]
        self.assertEqual(lib.in_container(flags, "refused", "10.1.1.2:9"), "refused")
        self.assertEqual(proxy.connects, [])


if __name__ == "__main__":
    unittest.main()
