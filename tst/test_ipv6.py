"""-6 and -nat64: IPv6 destinations through the proxy and NAT64 unmapping."""

import unittest

import lib


class IPv6Test(lib.ContainerTest):
    def test_ipv6_destination_through_proxy(self):
        echo = lib.EchoServer()
        proxy = lib.Socks5Server(backend=echo.addr)
        out = lib.in_container(["-F", proxy.addr, "-6"], "tcp", "[2001:db8::1]:8080")
        self.assertEqual(out, "echo:hello")
        self.assertEqual(proxy.connects, ["[2001:db8::1]:8080"])

    def test_ipv6_is_off_by_default(self):
        proxy = lib.Socks5Server()
        out = lib.in_container(["-F", proxy.addr], "refused", "[2001:db8::1]:8080")
        self.assertNotEqual(out, "connected")
        self.assertEqual(proxy.connects, [])

    def test_nat64_synthesized_destination_is_unmapped(self):
        echo = lib.EchoServer()
        proxy = lib.Socks5Server(backend=echo.addr)
        flags = ["-F", proxy.addr, "-6", "-nat64", "64:ff9b::/96"]
        out = lib.in_container(flags, "tcp", "[64:ff9b::c000:201]:8080")
        self.assertEqual(out, "echo:hello")
        self.assertEqual(proxy.connects, ["192.0.2.1:8080"])

    def test_tun_ipv6_subnet_is_refused(self):
        proxy = lib.Socks5Server()
        out = lib.in_container(["-F", proxy.addr, "-6"], "refused", "[2001:db8:1:1::2]:9")
        self.assertEqual(out, "refused")


if __name__ == "__main__":
    unittest.main()
