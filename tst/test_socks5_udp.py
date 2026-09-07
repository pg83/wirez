"""UDP through SOCKS5 UDP ASSOCIATE: relayed datagrams, a proxy that binds
its relay to an unspecified address, and one association per socket."""

import threading
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

    def test_replies_with_ipv4_mapped_addresses_reach_their_flow(self):
        echo = lib.UdpEchoServer()
        proxy = lib.Socks5Server(udp_backend=echo.addr, reply_v4_mapped=True)
        out = lib.in_container(["-F", proxy.addr], "udp-multi", "192.0.2.1:5353", "192.0.2.2:5354")
        self.assertEqual(out, "msg0 msg1")

    def test_association_dropped_by_the_proxy_is_reopened(self):
        echo = lib.UdpEchoServer()
        proxy = lib.Socks5Server(udp_backend=echo.addr)
        # the proxy ends the association between the two exchanges of one socket
        threading.Timer(1.0, proxy.drop_associations).start()
        out = lib.in_container(["-F", proxy.addr], "udp-twice", "192.0.2.1:5353", "2")
        self.assertEqual(out, "ping? ping?")
        self.assertEqual(proxy.associations, 2)

    def test_udp_without_proxy_support_times_out(self):
        proxy = lib.Socks5Server(udp_backend=lib.closed_udp_port())
        out = lib.in_container(["-F", proxy.addr], "udp", "192.0.2.1:5353")
        self.assertEqual(out, "timeout")


if __name__ == "__main__":
    unittest.main()
