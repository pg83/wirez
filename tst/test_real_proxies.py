"""Real proxy servers instead of the test fake: microsocks and 3proxy (SOCKS5,
3proxy with UDP), tinyproxy (HTTP CONNECT), with and without authentication.
TCP goes through curl and an HTTP server: a request/response exchange, which
is what these proxies are built for (microsocks does not forward half-closes)."""

import sys
import unittest

import lib

lib.reexec_in_netns(setup=lib.WORKLOAD_NETNS_SETUP)


class RealProxiesTest(lib.WorkloadTest):
    def setUp(self):
        super().setUp()
        lib.require_tools(self, "curl")
        (self.dir / "index.html").write_text("through a real proxy\n")
        self.http_port = lib.free_port()
        httpd = self.daemon([sys.executable, lib.HTTPD, lib.WORKLOAD_IPV4, self.http_port, self.dir])
        lib.wait_port(lib.WORKLOAD_IPV4, self.http_port, daemon=httpd)
        self.url = f"http://{lib.WORKLOAD_IPV4}:{self.http_port}/index.html"
        self.udp_echo = lib.UdpEchoServer(host=lib.WORKLOAD_IPV4)

    def assert_http(self, flags):
        out = lib.in_container_run(flags, ["curl", "-sS", "--max-time", "30", self.url]).stdout
        self.assertEqual(out, "through a real proxy\n")

    def assert_refused(self, flags):
        result = lib.in_container_run(flags, ["curl", "-sS", "--max-time", "30", self.url], check=False)
        self.assertNotEqual(result.returncode, 0)

    def start(self, argv, port, **kwargs):
        daemon = self.daemon(argv, **kwargs)
        lib.wait_port("127.0.0.1", port, daemon=daemon)
        return daemon

    def test_microsocks(self):
        lib.require_tools(self, "microsocks")
        port = lib.free_port("127.0.0.1")
        self.start(["microsocks", "-i", "127.0.0.1", "-p", port], port)
        self.assert_http(["-F", f"127.0.0.1:{port}"])

    def test_microsocks_with_authentication(self):
        lib.require_tools(self, "microsocks")
        port = lib.free_port("127.0.0.1")
        self.start(["microsocks", "-i", "127.0.0.1", "-p", port, "-u", "alice", "-P", "s3cret"], port)
        self.assert_http(["-F", f"socks5://alice:s3cret@127.0.0.1:{port}"])
        self.assert_refused(["-F", f"127.0.0.1:{port}"])

    def test_3proxy_tcp_and_udp(self):
        lib.require_tools(self, "3proxy")
        port = lib.free_port("127.0.0.1")
        config = self.dir / "3proxy.cfg"
        config.write_text(f"auth none\nallow *\nsocks -p{port} -i127.0.0.1 -e127.0.0.1\n")
        self.start(["3proxy", config], port)
        flags = ["-F", f"127.0.0.1:{port}"]
        self.assert_http(flags)
        self.assertEqual(lib.in_container(flags, "udp", self.udp_echo.addr), "ping?")

    def test_3proxy_with_authentication(self):
        lib.require_tools(self, "3proxy")
        port = lib.free_port("127.0.0.1")
        config = self.dir / "3proxy.cfg"
        config.write_text(f"users alice:CL:s3cret\nauth strong\nallow alice\nsocks -p{port} -i127.0.0.1 -e127.0.0.1\n")
        self.start(["3proxy", config], port)
        self.assert_http(["-F", f"socks5://alice:s3cret@127.0.0.1:{port}"])
        self.assert_refused(["-F", f"127.0.0.1:{port}"])

    def test_tinyproxy_http_connect(self):
        lib.require_tools(self, "tinyproxy")
        port = lib.free_port("127.0.0.1")
        config = self.dir / "tinyproxy.conf"
        config.write_text(f"Port {port}\nListen 127.0.0.1\nAllow 127.0.0.1\nTimeout 60\nMaxClients 50\nLogLevel Warning\n")
        self.start(["tinyproxy", "-d", "-c", config], port)
        self.assert_http(["-F", f"http://127.0.0.1:{port}"])


if __name__ == "__main__":
    unittest.main()
