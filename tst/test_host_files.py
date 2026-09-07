"""What the container gets as /etc/resolv.conf and /etc/hosts, with the
host's files replaced by known ones (bind mounts in a private mount
namespace): search domains and options are kept, an empty hosts file gets
only wirez's own entries."""

import os
import tempfile
import unittest

import lib

if not os.environ.get("WIREZ_TEST_NETNS"):
    _files = tempfile.mkdtemp(prefix="wirez-hostfiles-")
    with open(os.path.join(_files, "resolv.conf"), "w") as f:
        f.write("# by the test\nnameserver 10.99.0.1\nsearch corp.example internal\noptions ndots:2 timeout:1\n")
    open(os.path.join(_files, "hosts"), "w").close()
    lib.reexec_in_netns(setup=[
        ["mount", "--bind", os.path.join(_files, "resolv.conf"), "/etc/resolv.conf"],
        ["mount", "--bind", os.path.join(_files, "hosts"), "/etc/hosts"],
    ], mount=True)


class HostFilesTest(lib.ContainerTest):
    def setUp(self):
        self.proxy = lib.Socks5Server()

    def test_resolv_conf_with_local_resolver(self):
        dns = lib.DnsServer({})
        out = lib.in_container(["-F", self.proxy.addr, "-D", dns.addr], "file", "/etc/resolv.conf")
        self.assertEqual(out, "nameserver 127.0.0.1\nsearch corp.example internal\noptions ndots:2 timeout:1\n")

    def test_resolv_conf_without_local_resolver(self):
        out = lib.in_container(["-F", self.proxy.addr], "file", "/etc/resolv.conf")
        self.assertEqual(out, "nameserver 10.1.1.2\nsearch corp.example internal\noptions ndots:2 timeout:1\n")

    def test_hosts_from_an_empty_host_file(self):
        out = lib.in_container(["-F", self.proxy.addr], "file", "/etc/hosts")
        self.assertEqual(
            out,
            "127.0.0.1 localhost\n::1 localhost\n10.1.1.2 localhost\n"
            "127.0.0.1 wirez wirez.localdomain\n::1 wirez wirez.localdomain\n",
        )


if __name__ == "__main__":
    unittest.main()
