"""TLS with client certificates is passed through untouched: the server sees
the client's certificate, and rejects a client without one."""

import unittest

import lib

lib.reexec_in_netns(setup=lib.WORKLOAD_NETNS_SETUP)


class MutualTlsTest(lib.WorkloadTest):
    def setUp(self):
        super().setUp()
        lib.require_tools(self, "curl", "openssl")
        self.tls = lib.TlsMaterial(self.dir)
        (self.dir / "index.html").write_text("mutually authenticated\n")
        self.port = lib.free_port()
        self.server = self.daemon(
            ["openssl", "s_server", "-accept", f"{lib.WORKLOAD_IPV4}:{self.port}", "-cert", self.tls.server_cert,
             "-key", self.tls.server_key, "-CAfile", self.tls.ca, "-Verify", "1", "-WWW", "-quiet"],
            cwd=self.dir,
        )
        lib.wait_port(lib.WORKLOAD_IPV4, self.port, daemon=self.server)
        self.url = f"https://{lib.WORKLOAD_IPV4}:{self.port}/index.html"

    def test_client_certificate_is_accepted(self):
        out = lib.in_container_run(
            self.flags, ["curl", "-sS", "--max-time", "30", "--cacert", self.tls.ca,
                         "--cert", self.tls.client_cert, "--key", self.tls.client_key, self.url],
        ).stdout
        self.assertEqual(out, "mutually authenticated\n", self.server.output())
        self.assertEqual(self.proxy.connects, [f"{lib.WORKLOAD_IPV4}:{self.port}"])

    def test_missing_client_certificate_is_rejected(self):
        result = lib.in_container_run(
            self.flags, ["curl", "-sS", "--max-time", "30", "--cacert", self.tls.ca, self.url], check=False,
        )
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
