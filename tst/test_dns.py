"""The -D resolver: forwarding, AAAA policy, TCP, truncation, failover, and
what the container's resolv.conf looks like."""

import unittest

import dnswire
import lib

RECORDS = {
    "wirez.test.": ["192.0.2.1", "2001:db8::10"],
    "far.test.": ["198.51.100.1", "2607:6bc0::10"],
}


class DnsTest(lib.ContainerTest):
    def setUp(self):
        self.proxy = lib.Socks5Server()
        self.dns = lib.DnsServer(RECORDS)

    def flags(self, *extra, dns=None):
        return ["-F", self.proxy.addr, "-D", (dns or self.dns).addr, *extra]

    def test_a_query_is_forwarded_directly(self):
        out = lib.in_container(self.flags(), "dns", "wirez.test")
        self.assertEqual(out, "192.0.2.1")
        self.assertIn(("wirez.test.", dnswire.TYPE_A, "udp"), self.dns.queries)
        self.assertEqual(self.proxy.connects, [])
        self.assertEqual(self.proxy.associations, 0)

    def test_aaaa_is_answered_empty_without_ipv6(self):
        out = lib.in_container(self.flags(), "dns", "wirez.test", "AAAA")
        self.assertTrue(out.startswith("error:"), out)
        self.assertNotIn(dnswire.TYPE_AAAA, [qtype for _, qtype, _ in self.dns.queries])

    def test_aaaa_passes_with_ipv6_only_for_bypass_networks(self):
        flags = self.flags("-6", "-B", "2001:db8::/32")
        self.assertEqual(lib.in_container(flags, "dns", "wirez.test", "AAAA"), "2001:db8::10")
        self.assertTrue(lib.in_container(flags, "dns", "far.test", "AAAA").startswith("error:"))

    def test_resolver_answers_over_tcp(self):
        out = lib.in_container(self.flags(), "dns-tcp", "wirez.test")
        self.assertEqual(out, "192.0.2.1")

    def test_truncated_udp_answer_is_refetched_over_tcp(self):
        dns = lib.DnsServer(RECORDS, truncate_udp=True)
        out = lib.in_container(self.flags(dns=dns), "dns", "wirez.test")
        self.assertEqual(out, "192.0.2.1")
        self.assertIn(("wirez.test.", dnswire.TYPE_A, "udp"), dns.queries)
        self.assertIn(("wirez.test.", dnswire.TYPE_A, "tcp"), dns.queries)

    def test_dead_upstream_is_skipped(self):
        flags = ["-F", self.proxy.addr, "-D", lib.closed_udp_port(), "-D", self.dns.addr]
        out = lib.in_container(flags, "dns", "wirez.test")
        self.assertEqual(out, "192.0.2.1")

    def test_resolv_conf_points_at_resolver_and_keeps_host_options(self):
        out = lib.in_container(self.flags(), "file", "/etc/resolv.conf")
        lines = out.splitlines()
        self.assertEqual(lines[0], "nameserver 127.0.0.1")
        self.assertEqual([l for l in lines if l.startswith("nameserver")], ["nameserver 127.0.0.1"])
        with open("/etc/resolv.conf") as host:
            for line in host:
                fields = line.split()
                if fields and fields[0] in ("search", "domain", "options", "sortlist"):
                    self.assertIn(" ".join(fields), lines)

    def test_without_resolver_nameserver_is_the_tun_peer(self):
        out = lib.in_container(["-F", self.proxy.addr], "file", "/etc/resolv.conf")
        self.assertEqual(out.splitlines()[0], "nameserver 10.1.1.2")


if __name__ == "__main__":
    unittest.main()
