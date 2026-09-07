"""Chained -F hops: each hop's control connection goes through the previous one."""

import unittest

import lib


class ProxyChainTest(lib.ContainerTest):
    def test_two_socks5_hops(self):
        echo = lib.EchoServer()
        second = lib.Socks5Server(backend=echo.addr)
        first = lib.Socks5Server()
        out = lib.in_container(["-F", first.addr, "-F", second.addr], "tcp", "192.0.2.1:8080")
        self.assertEqual(out, "echo:hello")
        self.assertEqual(first.connects, [second.addr])
        self.assertEqual(second.connects, ["192.0.2.1:8080"])

    def test_socks5_then_http(self):
        echo = lib.EchoServer()
        second = lib.HttpConnectProxy(backend=echo.addr)
        first = lib.Socks5Server()
        out = lib.in_container(["-F", first.addr, "-F", f"http://{second.addr}"], "tcp", "192.0.2.1:8080")
        self.assertEqual(out, "echo:hello")
        self.assertEqual(first.connects, [second.addr])
        self.assertEqual(second.connects, ["192.0.2.1:8080"])

    def test_udp_through_two_socks5_hops(self):
        echo = lib.UdpEchoServer()
        second = lib.Socks5Server(udp_backend=echo.addr)
        first = lib.Socks5Server()
        out = lib.in_container(["-F", first.addr, "-F", second.addr], "udp", "192.0.2.1:5353")
        self.assertEqual(out, "ping?")
        self.assertEqual(first.associations, 1)
        self.assertEqual(second.associations, 1)


if __name__ == "__main__":
    unittest.main()
