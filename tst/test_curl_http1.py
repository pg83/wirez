"""curl over HTTP/1.1 through the proxy: small and large downloads, uploads,
and several requests over one kept-alive connection."""

import sys
import unittest

import lib

lib.reexec_in_netns(setup=lib.WORKLOAD_NETNS_SETUP)


class CurlHttp1Test(lib.WorkloadTest):
    def setUp(self):
        super().setUp()
        lib.require_tools(self, "curl")
        (self.dir / "index.html").write_text("hello from httpd\n")
        self.big, self.big_sha = lib.random_file(self.dir, "big.bin", 32 << 20)
        self.port = lib.free_port()
        self.httpd = self.daemon([sys.executable, lib.HTTPD, lib.WORKLOAD_IPV4, self.port, self.dir])
        lib.wait_port(lib.WORKLOAD_IPV4, self.port)
        self.base = f"http://{lib.WORKLOAD_IPV4}:{self.port}"

    def curl(self, *args):
        return lib.in_container_run(self.flags, ["curl", "-sS", "--max-time", "60", *args]).stdout

    def test_get(self):
        out = self.curl("-w", "\\n%{http_version}", f"{self.base}/index.html")
        self.assertEqual(out, "hello from httpd\n\n1.1")
        self.assertEqual(self.proxy.connects, [f"{lib.WORKLOAD_IPV4}:{self.port}"])

    def test_large_download(self):
        target = self.dir / "downloaded.bin"
        self.curl("-o", target, f"{self.base}/big.bin")
        self.assertEqual(lib.sha256_file(target), self.big_sha)

    def test_large_upload(self):
        out = self.curl("--data-binary", f"@{self.big}", f"{self.base}/upload")
        self.assertEqual(out, self.big_sha)

    def test_requests_share_a_kept_alive_connection(self):
        out = self.curl(f"{self.base}/index.html", f"{self.base}/index.html", f"{self.base}/index.html")
        self.assertEqual(out, "hello from httpd\n" * 3)
        self.assertEqual(len(self.proxy.connects), 1)


if __name__ == "__main__":
    unittest.main()
