"""Many connections and datagrams at once."""

import sys
import unittest

import lib

lib.reexec_in_netns(setup=lib.WORKLOAD_NETNS_SETUP)


class ParallelTest(lib.WorkloadTest):
    def test_two_hundred_concurrent_tcp_connections(self):
        echo = lib.EchoServer(host=lib.WORKLOAD_IPV4)
        self.assertEqual(lib.in_container(self.flags, "tcp-many", "200", echo.addr), "200/200")
        self.assertEqual(len(self.proxy.connects), 200)

    def test_curl_parallel_requests(self):
        lib.require_tools(self, "curl")
        (self.dir / "index.html").write_text("x\n")
        port = lib.free_port()
        self.daemon([sys.executable, lib.HTTPD, lib.WORKLOAD_IPV4, port, self.dir])
        lib.wait_port(lib.WORKLOAD_IPV4, port)
        urls = []
        for _ in range(100):
            urls += [f"http://{lib.WORKLOAD_IPV4}:{port}/index.html", "-o", "/dev/null"]
        out = lib.in_container_run(
            self.flags, ["curl", "-sS", "--max-time", "60", "--parallel", "--parallel-max", "40",
                         "-w", "%{http_code}\\n", *urls],
        ).stdout
        self.assertEqual(out.split(), ["200"] * 100)

    def test_udp_burst_from_one_socket(self):
        echo = lib.UdpEchoServer(host=lib.WORKLOAD_IPV4)
        self.assertEqual(lib.in_container(self.flags, "udp-burst", "500", echo.addr), "500/500")
        self.assertEqual(self.proxy.associations, 1)


if __name__ == "__main__":
    unittest.main()
