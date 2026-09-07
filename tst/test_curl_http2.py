"""curl over HTTP/2 (cleartext, prior knowledge) against nghttpd."""

import unittest

import lib

lib.reexec_in_netns(setup=lib.WORKLOAD_NETNS_SETUP)


class CurlHttp2Test(lib.WorkloadTest):
    def setUp(self):
        super().setUp()
        lib.require_tools(self, "curl", "nghttpd")
        (self.dir / "index.html").write_text("hello over h2\n")
        self.big, self.big_sha = lib.random_file(self.dir, "big.bin", 16 << 20)
        self.port = lib.free_port()
        self.daemon(["nghttpd", "--no-tls", "-a", lib.WORKLOAD_IPV4, "-d", self.dir, self.port])
        lib.wait_port(lib.WORKLOAD_IPV4, self.port)
        self.base = f"http://{lib.WORKLOAD_IPV4}:{self.port}"

    def curl(self, *args):
        return lib.in_container_run(
            self.flags, ["curl", "-sS", "--max-time", "60", "--http2-prior-knowledge", *args],
        ).stdout

    def test_get(self):
        out = self.curl("-w", "\\n%{http_version}", f"{self.base}/index.html")
        self.assertEqual(out, "hello over h2\n\n2")

    def test_large_download(self):
        target = self.dir / "downloaded.bin"
        self.curl("-o", target, f"{self.base}/big.bin")
        self.assertEqual(lib.sha256_file(target), self.big_sha)

    def test_multiplexed_requests_share_one_connection(self):
        out = self.curl("--parallel", f"{self.base}/index.html", f"{self.base}/index.html", f"{self.base}/index.html")
        self.assertEqual(out, "hello over h2\n" * 3)
        self.assertEqual(len(self.proxy.connects), 1)


if __name__ == "__main__":
    unittest.main()
