"""iperf3 through the proxy: TCP both ways and UDP."""

import json
import unittest

import lib

lib.reexec_in_netns(setup=lib.WORKLOAD_NETNS_SETUP)


class Iperf3Test(lib.WorkloadTest):
    def setUp(self):
        super().setUp()
        lib.require_tools(self, "iperf3")
        self.port = lib.free_port()
        self.server = self.daemon(["iperf3", "-s", "-B", lib.WORKLOAD_IPV4, "-p", self.port])
        lib.wait_port(lib.WORKLOAD_IPV4, self.port, daemon=self.server)

    def iperf(self, *args):
        result = lib.in_container_run(
            self.flags, ["iperf3", "-c", lib.WORKLOAD_IPV4, "-p", self.port, "-t", "2", "-J", *args], timeout=120,
        )
        report = json.loads(result.stdout)
        self.assertNotIn("error", report, self.server.output())
        return report["end"]

    def test_tcp_upload(self):
        end = self.iperf()
        self.assertGreater(end["sum_received"]["bits_per_second"], 1e6)

    def test_tcp_download(self):
        end = self.iperf("-R")
        self.assertGreater(end["sum_received"]["bits_per_second"], 1e6)

    def test_udp(self):
        end = self.iperf("-u", "-b", "20M")
        self.assertGreater(end["sum"]["packets"], 100)
        self.assertLess(end["sum"]["lost_percent"], 20)


if __name__ == "__main__":
    unittest.main()
