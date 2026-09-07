"""-L mappings and the refusal of the TUN subnet without one."""

import unittest

import lib


class LocalMappingTest(lib.ContainerTest):
    def test_tcp_mapping_bypasses_the_proxy(self):
        echo = lib.EchoServer()
        proxy = lib.Socks5Server()
        flags = ["-F", proxy.addr, "-L", f"10.10.10.10:2345:{echo.addr}/tcp"]
        self.assertEqual(lib.in_container(flags, "tcp", "10.10.10.10:2345"), "echo:hello")
        self.assertEqual(proxy.connects, [])

    def test_port_only_udp_mapping(self):
        echo = lib.UdpEchoServer()
        proxy = lib.Socks5Server()
        flags = ["-F", proxy.addr, "-L", f"5353:{echo.addr}/udp"]
        self.assertEqual(lib.in_container(flags, "udp", "192.0.2.1:5353"), "ping?")
        self.assertEqual(proxy.associations, 0)

    def test_tun_peer_is_refused_without_mapping(self):
        proxy = lib.Socks5Server()
        self.assertEqual(lib.in_container(["-F", proxy.addr], "refused", "10.1.1.2:9"), "refused")
        self.assertEqual(proxy.connects, [])

    def test_mapping_redirects_the_tun_peer(self):
        echo = lib.EchoServer()
        proxy = lib.Socks5Server()
        flags = ["-F", proxy.addr, "-L", f"10.1.1.2:9:{echo.addr}/tcp"]
        self.assertEqual(lib.in_container(flags, "tcp", "10.1.1.2:9"), "echo:hello")

    def test_mapping_wins_over_bypass(self):
        echo = lib.EchoServer()
        proxy = lib.Socks5Server()
        flags = ["-F", proxy.addr, "-B", "10.0.0.0/8", "-L", f"10.1.1.2:9:{echo.addr}/tcp"]
        self.assertEqual(lib.in_container(flags, "tcp", "10.1.1.2:9"), "echo:hello")
        self.assertEqual(lib.in_container(flags, "refused", "10.1.1.2:10"), "refused")

    def test_bad_protocol_is_rejected(self):
        result = lib.wirez("-F", "127.0.0.1:1", "-L", "53:1.1.1.1:53/tpc", "--", "true", check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("tpc", result.stderr)


if __name__ == "__main__":
    unittest.main()
