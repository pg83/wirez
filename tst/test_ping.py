"""ICMP echo is answered inside the container for any address."""

import unittest

import lib


class PingTest(lib.ContainerTest):
    def test_ipv4_ping(self):
        proxy = lib.Socks5Server()
        self.assertEqual(lib.in_container(["-F", proxy.addr], "ping", "192.0.2.1"), "reply")

    def test_ipv6_ping(self):
        proxy = lib.Socks5Server()
        self.assertEqual(lib.in_container(["-F", proxy.addr, "-6"], "ping", "2001:db8::1"), "reply")


if __name__ == "__main__":
    unittest.main()
