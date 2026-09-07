"""TCP through an HTTP CONNECT proxy, and the absence of UDP there."""

import unittest

import lib


class HttpConnectTest(lib.ContainerTest):
    def test_connect_through_http_proxy(self):
        echo = lib.EchoServer()
        proxy = lib.HttpConnectProxy(backend=echo.addr)
        out = lib.in_container(["-F", f"http://{proxy.addr}"], "tcp", "192.0.2.1:8080")
        self.assertEqual(out, "echo:hello")
        self.assertEqual(proxy.connects, ["192.0.2.1:8080"])

    def test_bytes_after_response_survive(self):
        echo = lib.EchoServer(greeting=b"220 smtp\r\n")
        proxy = lib.HttpConnectProxy(backend=echo.addr, banner=b"first bytes")
        out = lib.in_container(["-F", f"http://{proxy.addr}"], "tcp", "192.0.2.1:25")
        self.assertEqual(out, "first bytes220 smtp\r\necho:hello")

    def test_authentication(self):
        echo = lib.EchoServer()
        proxy = lib.HttpConnectProxy(backend=echo.addr, user="alice", password="s3cret")
        out = lib.in_container(["-F", f"http://alice:s3cret@{proxy.addr}"], "tcp", "192.0.2.1:80")
        self.assertEqual(out, "echo:hello")
        out = lib.in_container(["-F", f"http://{proxy.addr}"], "refused", "192.0.2.1:80")
        self.assertEqual(out, "refused")

    def test_unreachable_destination_is_refused(self):
        proxy = lib.HttpConnectProxy(backend=lib.closed_tcp_port())
        out = lib.in_container(["-F", f"http://{proxy.addr}"], "refused", "192.0.2.1:9")
        self.assertEqual(out, "refused")

    def test_udp_is_refused_through_an_http_hop(self):
        echo = lib.UdpEchoServer()
        proxy = lib.HttpConnectProxy()
        out = lib.in_container(["-F", f"http://{proxy.addr}"], "udp", echo.addr)
        self.assertEqual(out, "timeout")
        self.assertEqual(proxy.connects, [])


if __name__ == "__main__":
    unittest.main()
