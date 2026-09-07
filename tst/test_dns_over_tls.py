"""DNS over TLS from inside the container: dig +tls to a resolver reached
directly via -B, and through the proxy."""

import unittest

import lib

lib.reexec_in_netns(setup=lib.WORKLOAD_NETNS_SETUP)


class DnsOverTlsTest(lib.WorkloadTest):
    def setUp(self):
        super().setUp()
        lib.require_tools(self, "dig", "socat", "openssl")
        self.tls = lib.TlsMaterial(self.dir)
        self.dns = lib.DnsServer({"wirez.test.": ["192.0.2.1"]})
        self.port = lib.free_port()
        self.dot = self.daemon([
            "socat",
            f"openssl-listen:{self.port},bind={lib.WORKLOAD_IPV4},cert={self.tls.server_cert},key={self.tls.server_key},verify=0,reuseaddr,fork",
            f"tcp:127.0.0.1:{self.dns.port}",
        ])
        lib.wait_port(lib.WORKLOAD_IPV4, self.port, daemon=self.dot)

    def dig(self, flags):
        return lib.in_container_run(
            flags, ["dig", f"@{lib.WORKLOAD_IPV4}", "-p", str(self.port), "+tls", f"+tls-ca={self.tls.ca}",
                    "+time=5", "+tries=1", "wirez.test", "A", "+short"],
        ).stdout

    def test_direct_via_bypass(self):
        self.assertEqual(self.dig([*self.flags, "-B", "192.0.2.0/24"]), "192.0.2.1\n")
        self.assertEqual(self.proxy.connects, [])
        self.assertIn(("wirez.test.", 1, "tcp"), self.dns.queries)

    def test_through_the_proxy(self):
        self.assertEqual(self.dig(self.flags), "192.0.2.1\n")
        self.assertEqual(self.proxy.connects, [f"{lib.WORKLOAD_IPV4}:{self.port}"])


if __name__ == "__main__":
    unittest.main()
