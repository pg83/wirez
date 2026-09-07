"""The -D resolver: forwarding, AAAA policy, TCP, truncation, failover, and
what the container's resolv.conf looks like."""

import unittest

import dnswire
import lib

RECORDS = {
    "wirez.test.": ["192.0.2.1", "2001:db8::10"],
    "far.test.": ["198.51.100.1", "2607:6bc0::10"],
    # one reachable address among unreachable ones keeps the whole answer
    "mixed.test.": ["2607:6bc0::10", "2001:db8::20"],
    # a DNS64-synthesized address counts by the IPv4 it embeds
    "nat64.test.": ["64:ff9b::c000:201"],
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

    def test_blocked_aaaa_is_nodata_on_the_wire(self):
        # NOERROR with the question echoed and no records, so resolvers fall
        # back to A instead of treating the name as missing
        out = lib.in_container(self.flags(), "dns-raw", "wirez.test", str(dnswire.TYPE_AAAA))
        self.assertEqual(
            out,
            "id=0x4242 response=1 rcode=0 tc=0 question=wirez.test./28 questions=1 answers=0 ips=",
        )

    def test_aaaa_passes_with_ipv6_only_for_bypass_networks(self):
        flags = self.flags("-6", "-B", "2001:db8::/32")
        self.assertEqual(lib.in_container(flags, "dns", "wirez.test", "AAAA"), "2001:db8::10")
        self.assertTrue(lib.in_container(flags, "dns", "far.test", "AAAA").startswith("error:"))
        self.assertEqual(lib.in_container(flags, "dns", "mixed.test", "AAAA"), "2001:db8::20,2607:6bc0::10")

    def test_aaaa_policy_unmaps_nat64_addresses(self):
        flags = self.flags("-6", "-nat64", "64:ff9b::/96", "-B", "192.0.2.0/24")
        self.assertEqual(lib.in_container(flags, "dns", "nat64.test", "AAAA"), "64:ff9b::c000:201")
        self.assertTrue(lib.in_container(flags, "dns", "far.test", "AAAA").startswith("error:"))

    def test_garbage_aaaa_answers_become_nodata(self):
        # a reply that is no DNS message at all, and one whose question
        # section is cut off: neither is let through
        for garbage in (b"\x01", b"\x42\x42\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00"):
            with self.subTest(garbage=garbage):
                dns = lib.DnsServer(RECORDS, garbage=garbage)
                out = lib.in_container(self.flags("-6", "-B", "2001:db8::/32", dns=dns), "dns", "wirez.test", "AAAA")
                self.assertTrue(out.startswith("error:"), out)

    def test_bare_upstream_addresses_imply_port_53(self):
        # nothing is resolved here, the log shows how -D was understood
        result = lib.in_container(
            ["-F", self.proxy.addr, "-D", "192.0.2.53", "-D", "2001:db8::53", "-D", "192.0.2.54:5353", "-v"],
            "id", check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('upstreams="[192.0.2.53:53 [2001:db8::53]:53 192.0.2.54:5353]"', result.stderr)

    def test_resolver_answers_over_tcp(self):
        out = lib.in_container(self.flags(), "dns-tcp", "wirez.test")
        self.assertEqual(out, "192.0.2.1")

    def test_truncated_udp_answer_is_refetched_over_tcp(self):
        dns = lib.DnsServer(RECORDS, truncate_udp=True)
        out = lib.in_container(self.flags(dns=dns), "dns-raw", "wirez.test", str(dnswire.TYPE_A))
        self.assertIn("tc=0 question=wirez.test./1 questions=1 answers=1 ips=192.0.2.1", out)
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
