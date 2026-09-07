"""-B networks go direct; everything else goes through the proxy."""

import unittest

import lib


class BypassTest(lib.ContainerTest):
    def test_bypass_network_goes_direct(self):
        ip = lib.host_ip()
        if ip is None:
            self.skipTest("host has no non-loopback IPv4 address")
        echo = lib.EchoServer(host="0.0.0.0")
        proxy = lib.Socks5Server()
        flags = ["-F", proxy.addr, "-B", f"{ip}/32"]
        self.assertEqual(lib.in_container(flags, "tcp", f"{ip}:{echo.port}"), "echo:hello")
        self.assertEqual(proxy.connects, [])

    def test_destinations_outside_bypass_use_the_proxy(self):
        echo = lib.EchoServer()
        proxy = lib.Socks5Server(backend=echo.addr)
        flags = ["-F", proxy.addr, "-B", "198.51.100.0/24"]
        self.assertEqual(lib.in_container(flags, "tcp", "192.0.2.1:8080"), "echo:hello")
        self.assertEqual(proxy.connects, ["192.0.2.1:8080"])


if __name__ == "__main__":
    unittest.main()
