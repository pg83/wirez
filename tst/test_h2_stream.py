"""A long-lived HTTP/2 stream: the server sends a chunk every second and the
client must see each one as it comes, not the whole body at the end."""

import time
import unittest

import lib

lib.reexec_in_netns(setup=lib.WORKLOAD_NETNS_SETUP)


class H2StreamTest(lib.WorkloadTest):
    def setUp(self):
        super().setUp()
        lib.require_tools(self, "curl", "hypercorn")
        self.port = lib.free_port()
        self.server = self.daemon(
            ["hypercorn", "--bind", f"{lib.WORKLOAD_IPV4}:{self.port}", "h2stream:app"],
            cwd=lib.Path(lib.HTTPD).parent,
        )
        lib.wait_port(lib.WORKLOAD_IPV4, self.port, daemon=self.server)
        self.url = f"http://{lib.WORKLOAD_IPV4}:{self.port}/"

    def test_chunks_arrive_over_time(self):
        start = time.monotonic()
        result = lib.in_container_run(
            self.flags, ["curl", "-sS", "-N", "--http2-prior-knowledge", "--max-time", "60",
                         "-w", "\\n%{http_version} %{time_starttransfer}", self.url],
        )
        elapsed = time.monotonic() - start
        body, _, stats = result.stdout.rpartition("\n")
        version, first_byte = stats.split()
        self.assertEqual(body, "".join(f"tick {i}\n" for i in range(5)) + "done\n")
        self.assertEqual(version, "2")
        self.assertGreater(elapsed, 4)
        # the first chunk was delivered long before the last one
        self.assertLess(float(first_byte), 2)
        self.assertEqual(self.proxy.connects, [f"{lib.WORKLOAD_IPV4}:{self.port}"])

    def test_streamed_upload(self):
        big, _ = lib.random_file(self.dir, "big.bin", 8 << 20)
        out = lib.in_container_run(
            self.flags, ["curl", "-sS", "--http2-prior-knowledge", "--max-time", "60", "--data-binary", f"@{big}", self.url],
        ).stdout
        self.assertEqual(out, f"received {8 << 20}\n")


if __name__ == "__main__":
    unittest.main()
