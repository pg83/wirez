"""UDP through SOCKS5 UDP ASSOCIATE: relayed datagrams, a proxy that binds
its relay to an unspecified address, and one association per socket."""

import unittest

import lib


class Socks5UdpTest(lib.ContainerTest):
    def test_udp_through_proxy(self):
        # the fake proxy always names 0.0.0.0 as its relay, as some real ones do
        echo = lib.UdpEchoServer()
        proxy = lib.Socks5Server(udp_backend=echo.addr)
        out = lib.in_container(["-F", proxy.addr], "udp", "192.0.2.1:5353")
        self.assertEqual(out, "ping?")
        self.assertEqual(proxy.associations, 1)

    def test_flows_of_one_socket_share_an_association(self):
        echo = lib.UdpEchoServer()
        proxy = lib.Socks5Server(udp_backend=echo.addr)
        out = lib.in_container(["-F", proxy.addr], "udp-multi", "192.0.2.1:5353", "192.0.2.2:5354", "192.0.2.3:5355")
        self.assertEqual(out, "msg0 msg1 msg2")
        self.assertEqual(proxy.associations, 1)

    def test_udp_without_proxy_support_times_out(self):
        proxy = lib.Socks5Server(udp_backend=lib.closed_udp_port())
        out = lib.in_container(["-F", proxy.addr], "udp", "192.0.2.1:5353")
        self.assertEqual(out, "timeout")


if __name__ == "__main__":
    unittest.main()
