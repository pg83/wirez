"""TCP through a SOCKS5 proxy: CONNECT, half-close, bytes right after the
proxy's reply, authentication, refusal of unreachable destinations."""

import unittest

import lib


class Socks5TcpTest(lib.ContainerTest):
    def test_connect_through_proxy(self):
        echo = lib.EchoServer()
        proxy = lib.Socks5Server(backend=echo.addr)
        out = lib.in_container(["-F", proxy.addr], "tcp", "192.0.2.1:8080")
        self.assertEqual(out, "echo:hello")
        self.assertEqual(proxy.connects, ["192.0.2.1:8080"])

    def test_server_speaks_first_and_bytes_after_reply_survive(self):
        echo = lib.EchoServer(greeting=b"SSH-2.0-test\r\n")
        proxy = lib.Socks5Server(backend=echo.addr, banner=b"220 banner\r\n")
        out = lib.in_container(["-F", proxy.addr], "tcp", "192.0.2.1:22")
        self.assertEqual(out, "220 banner\r\nSSH-2.0-test\r\necho:hello")

    def test_authentication(self):
        echo = lib.EchoServer()
        proxy = lib.Socks5Server(backend=echo.addr, user="alice", password="s3cret")
        out = lib.in_container(["-F", f"socks5://alice:s3cret@{proxy.addr}"], "tcp", "192.0.2.1:80")
        self.assertEqual(out, "echo:hello")
        out = lib.in_container(["-F", f"socks5://alice:wrong@{proxy.addr}"], "refused", "192.0.2.1:80")
        self.assertEqual(out, "refused")
        out = lib.in_container(["-F", proxy.addr], "refused", "192.0.2.1:80")
        self.assertEqual(out, "refused")

    def test_unreachable_destination_is_refused(self):
        proxy = lib.Socks5Server(backend=lib.closed_tcp_port())
        out = lib.in_container(["-F", proxy.addr], "refused", "192.0.2.1:9")
        self.assertEqual(out, "refused")
        self.assertEqual(proxy.connects, ["192.0.2.1:9"])

    def test_socks5h_scheme_is_accepted(self):
        echo = lib.EchoServer()
        proxy = lib.Socks5Server(backend=echo.addr)
        out = lib.in_container(["-F", f"socks5h://{proxy.addr}"], "tcp", "192.0.2.1:8080")
        self.assertEqual(out, "echo:hello")


if __name__ == "__main__":
    unittest.main()
