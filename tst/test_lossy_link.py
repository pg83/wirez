"""A link with latency and packet loss (netem on the namespace's loopback):
TCP and QUIC transfers through the proxy still arrive intact."""

import sys
import unittest

import lib

lib.reexec_in_netns(setup=[
    *lib.WORKLOAD_NETNS_SETUP,
    ["tc", "qdisc", "add", "dev", "lo", "root", "netem", "delay", "10ms", "loss", "2%"],
])


class LossyLinkTest(lib.WorkloadTest):
    def setUp(self):
        super().setUp()
        lib.require_tools(self, "curl")
        self.big, self.big_sha = lib.random_file(self.dir, "big.bin", 4 << 20)

    def test_http1_download_survives_loss(self):
        port = lib.free_port()
        httpd = self.daemon([sys.executable, lib.HTTPD, lib.WORKLOAD_IPV4, port, self.dir])
        lib.wait_port(lib.WORKLOAD_IPV4, port, daemon=httpd)
        target = self.dir / "downloaded.bin"
        lib.in_container_run(self.flags, ["curl", "-sS", "--max-time", "120", "-o", target, f"http://{lib.WORKLOAD_IPV4}:{port}/big.bin"])
        self.assertEqual(lib.sha256_file(target), self.big_sha)

    def test_http3_download_survives_loss(self):
        lib.require_tools(self, "caddy")
        port = lib.free_port()
        (self.dir / "Caddyfile").write_text(
            "{\n\tadmin off\n\tauto_https disable_redirects\n\tskip_install_trust\n}\n"
            f"https://{lib.WORKLOAD_IPV4}:{port} {{\n\ttls internal\n\troot * {self.dir}\n\tfile_server\n}}\n"
        )
        for name in ("data", "config"):
            (self.dir / name).mkdir()
        env = lib.wirez_env({
            "HOME": str(self.dir), "XDG_DATA_HOME": str(self.dir / "data"), "XDG_CONFIG_HOME": str(self.dir / "config"),
        })
        caddy = self.daemon(["caddy", "run", "--config", self.dir / "Caddyfile", "--adapter", "caddyfile"], env=env)
        lib.wait_tls(lib.WORKLOAD_IPV4, port, daemon=caddy)
        target = self.dir / "downloaded.bin"
        lib.in_container_run(
            self.flags, ["curl", "-sS", "-k", "--http3-only", "--max-time", "120", "-o", target, f"https://{lib.WORKLOAD_IPV4}:{port}/big.bin"],
        )
        self.assertEqual(lib.sha256_file(target), self.big_sha, caddy.output())


if __name__ == "__main__":
    unittest.main()
