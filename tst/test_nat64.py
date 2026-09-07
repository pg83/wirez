"""-nat64 on an IPv6-only host: bypassed IPv4 destinations are dialed through
the NAT64 prefix. The test runs in its own network namespace where the
synthesized address is on loopback, so a server bound to it stands in for the
NAT64 gateway and the real destination."""

import unittest

import lib

PREFIX = "64:ff9b::/96"
# 192.0.2.1 embedded in the prefix
SYNTHESIZED = "64:ff9b::c000:201"

lib.reexec_in_netns(setup=[["ip", "-6", "addr", "add", f"{SYNTHESIZED}/128", "dev", "lo"]])


class NAT64Test(lib.ContainerTest):
    def setUp(self):
        self.proxy = lib.Socks5Server()
        self.flags = ["-F", self.proxy.addr, "-B", "192.0.2.0/24", "-nat64", PREFIX]

    def test_bypassed_ipv4_tcp_is_dialed_through_the_prefix(self):
        echo = lib.EchoServer(host=SYNTHESIZED)
        self.assertEqual(lib.in_container(self.flags, "tcp", f"192.0.2.1:{echo.port}"), "echo:hello")
        self.assertEqual(self.proxy.connects, [])

    def test_bypassed_ipv4_udp_is_dialed_through_the_prefix(self):
        echo = lib.UdpEchoServer(host=SYNTHESIZED)
        self.assertEqual(lib.in_container(self.flags, "udp", f"192.0.2.1:{echo.port}"), "ping?")
        self.assertEqual(self.proxy.associations, 0)

    def test_synthesized_destination_is_unmapped_before_the_bypass_check(self):
        # the container (DNS64 gave it an IPv6 address) dials the synthesized
        # address; it unmaps to a bypassed IPv4 and goes direct, through NAT64
        echo = lib.EchoServer(host=SYNTHESIZED)
        flags = [*self.flags, "-6"]
        self.assertEqual(lib.in_container(flags, "tcp", f"[{SYNTHESIZED}]:{echo.port}"), "echo:hello")
        self.assertEqual(self.proxy.connects, [])

    def test_synthesized_destination_outside_bypass_reaches_the_proxy_as_ipv4(self):
        echo = lib.EchoServer()
        proxy = lib.Socks5Server(backend=echo.addr)
        flags = ["-F", proxy.addr, "-B", "198.51.100.0/24", "-nat64", PREFIX, "-6"]
        self.assertEqual(lib.in_container(flags, "tcp", f"[{SYNTHESIZED}]:8080"), "echo:hello")
        self.assertEqual(proxy.connects, ["192.0.2.1:8080"])

    def test_mapping_is_not_run_through_the_prefix(self):
        echo = lib.EchoServer()
        flags = [*self.flags, "-L", f"192.0.2.1:9:{echo.addr}/tcp"]
        self.assertEqual(lib.in_container(flags, "tcp", "192.0.2.1:9"), "echo:hello")

    def test_without_the_flag_bypassed_ipv4_is_dialed_as_ipv4(self):
        echo = lib.EchoServer(host=SYNTHESIZED)
        flags = ["-F", self.proxy.addr, "-B", "192.0.2.0/24"]
        self.assertEqual(lib.in_container(flags, "refused", f"192.0.2.1:{echo.port}"), "refused")


if __name__ == "__main__":
    unittest.main()
