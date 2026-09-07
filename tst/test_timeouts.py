"""-tcp-timeout, its absence by default, and -connect-timeout."""

import time
import unittest

import lib


class TimeoutsTest(lib.ContainerTest):
    def test_idle_connection_is_closed_with_tcp_timeout(self):
        silent = lib.SilentServer()
        proxy = lib.Socks5Server(backend=silent.addr)
        flags = ["-F", proxy.addr, "-tcp-timeout", "300ms"]
        self.assertEqual(lib.in_container(flags, "idle", "192.0.2.1:80", "1.5"), "closed")

    def test_idle_connection_survives_by_default(self):
        echo = lib.EchoServer()
        proxy = lib.Socks5Server(backend=echo.addr)
        self.assertEqual(lib.in_container(["-F", proxy.addr], "idle", "192.0.2.1:80", "1.5"), "open")

    def test_connect_timeout_bounds_the_proxy_handshake(self):
        blackhole = lib.SilentServer()
        start = time.monotonic()
        out = lib.in_container(["-F", blackhole.addr, "-connect-timeout", "1s"], "refused", "192.0.2.1:80")
        self.assertEqual(out, "refused")
        self.assertLess(time.monotonic() - start, 6)


if __name__ == "__main__":
    unittest.main()
