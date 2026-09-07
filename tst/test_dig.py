"""dig against the -D resolver: UDP, TCP, and the empty AAAA answer."""

import unittest

import lib

lib.reexec_in_netns(setup=lib.WORKLOAD_NETNS_SETUP)


class DigTest(lib.WorkloadTest):
    def setUp(self):
        super().setUp()
        lib.require_tools(self, "dig")
        self.dns = lib.DnsServer({"wirez.test.": ["192.0.2.1", "2001:db8::10"]})
        self.flags = ["-F", self.proxy.addr, "-D", self.dns.addr]

    def dig(self, *args):
        return lib.in_container_run(self.flags, ["dig", "@127.0.0.1", "+time=5", "+tries=1", *args]).stdout

    def test_a_over_udp(self):
        self.assertEqual(self.dig("wirez.test", "A", "+short"), "192.0.2.1\n")
        self.assertEqual(self.proxy.connects, [])
        self.assertEqual(self.proxy.associations, 0)

    def test_a_over_tcp(self):
        self.assertEqual(self.dig("+tcp", "wirez.test", "A", "+short"), "192.0.2.1\n")

    def test_aaaa_is_nodata(self):
        out = self.dig("wirez.test", "AAAA", "+noall", "+comments", "+answer")
        self.assertIn("status: NOERROR", out)
        self.assertIn("ANSWER: 0", out)


if __name__ == "__main__":
    unittest.main()
