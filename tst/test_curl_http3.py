"""curl over HTTP/3 (QUIC over UDP through the proxy's UDP ASSOCIATE) and
HTTP/2 over TLS against caddy with a self-signed certificate."""

import unittest

import lib

lib.reexec_in_netns(setup=lib.WORKLOAD_NETNS_SETUP)


class CurlHttp3Test(lib.WorkloadTest):
    def setUp(self):
        super().setUp()
        lib.require_tools(self, "curl", "caddy")
        (self.dir / "index.html").write_text("hello over quic\n")
        self.big, self.big_sha = lib.random_file(self.dir, "big.bin", 16 << 20)
        self.port = lib.free_port()
        caddyfile = self.dir / "Caddyfile"
        caddyfile.write_text(
            "{\n\tadmin off\n\tauto_https disable_redirects\n\tskip_install_trust\n}\n"
            f"https://{lib.WORKLOAD_IPV4}:{self.port} {{\n\ttls internal\n\troot * {self.dir}\n\tfile_server\n}}\n"
        )
        for name in ("data", "config"):
            (self.dir / name).mkdir()
        env = lib.wirez_env({
            "HOME": str(self.dir),
            "XDG_DATA_HOME": str(self.dir / "data"),
            "XDG_CONFIG_HOME": str(self.dir / "config"),
        })
        self.caddy = self.daemon(["caddy", "run", "--config", caddyfile, "--adapter", "caddyfile"], env=env)
        lib.wait_tls(lib.WORKLOAD_IPV4, self.port, daemon=self.caddy)
        self.base = f"https://{lib.WORKLOAD_IPV4}:{self.port}"

    def curl(self, *args):
        return lib.in_container_run(self.flags, ["curl", "-sS", "-k", "--max-time", "60", *args]).stdout

    def test_http3(self):
        out = self.curl("--http3-only", "-w", "\\n%{http_version}", f"{self.base}/index.html")
        self.assertEqual(out, "hello over quic\n\n3", self.caddy.output())
        self.assertEqual(self.proxy.associations, 1)

    def test_http3_large_download(self):
        target = self.dir / "downloaded.bin"
        self.curl("--http3-only", "-o", target, f"{self.base}/big.bin")
        self.assertEqual(lib.sha256_file(target), self.big_sha, self.caddy.output())

    def test_http2_over_tls(self):
        out = self.curl("--http2", "-w", "\\n%{http_version}", f"{self.base}/index.html")
        self.assertEqual(out, "hello over quic\n\n2")
        self.assertEqual(self.proxy.connects, [f"{lib.WORKLOAD_IPV4}:{self.port}"])


if __name__ == "__main__":
    unittest.main()
