"""UDP datagrams of every size, up to the largest IP allows: the big ones are
fragmented on the way into the container's stack and must come out whole."""

import unittest

import lib

lib.reexec_in_netns(setup=lib.WORKLOAD_NETNS_SETUP)


class UdpSizesTest(lib.WorkloadTest):
    def setUp(self):
        super().setUp()
        self.echo = lib.UdpEchoServer(host=lib.WORKLOAD_IPV4)

    def test_sizes(self):
        # 65497 is the most a SOCKS5 relay can carry: the proxy receives the
        # payload plus a 10-byte header in one UDP datagram, whose maximum is
        # 65507 (SOCKS5 fragmentation, which would lift that, is unsupported)
        for size in (1, 1400, 8000, 32768, 60000, 65497):
            with self.subTest(size=size):
                self.assertEqual(lib.in_container(self.flags, "udp-size", str(size), self.echo.addr), f"{size} same")


if __name__ == "__main__":
    unittest.main()
