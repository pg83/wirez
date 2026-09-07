"""The command line itself: usage, flag validation, logging levels, and the
UDP idle timeout flag."""

import unittest

import lib


class CliTest(unittest.TestCase):
    def test_no_arguments_prints_usage(self):
        result = lib.wirez(check=False)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Usage: wirez", result.stderr)
        for flag in ("-F", "-L", "-B", "-D", "-6", "-nat64", "-hostname", "-connect-timeout", "-tcp-timeout",
                     "-udp-timeout", "-v", "-q", "-uid", "-gid"):
            self.assertIn(f"\n  {flag} ", result.stderr)

    def test_missing_proxy_is_an_error(self):
        result = lib.wirez("--", "true", check=False)
        self.assertEqual(result.returncode, 1)
        self.assertIn("forward proxies list is empty", result.stderr)

    def test_invalid_values_are_rejected(self):
        for flags, needle in [
            (["-F", "ftp://x:1"], "unsupported proxy scheme"),
            (["-F", "127.0.0.1:1", "-B", "10.0.0.0/33"], "10.0.0.0/33"),
            (["-F", "127.0.0.1:1", "-D", "not-an-ip"], "invalid -D"),
            (["-F", "127.0.0.1:1", "-nat64", "64:ff9b::/64"], "must be an IPv6 /96"),
            (["-F", "127.0.0.1:1", "-tcp-timeout", "-1s"], "timeouts must be positive"),
            (["-F", "127.0.0.1:1", "-uid", "-1"], "uid is negative"),
            (["-F", "127.0.0.1:1", "-gid", "-1"], "gid is negative"),
            (["-F", "127.0.0.1:1", "-D", ""], "empty -D dns address"),
            (["-F", "127.0.0.1:1", "-L", "53:[bad]:53/udp"], "invalid IPv6 address"),
            (["-F", "127.0.0.1:1", "-L", "53:1.1.1.1]:53"], "invalid IPv6 address"),
            (["-F", "127.0.0.1:1", "-L", "53:x[::1]:53"], "missing colon before host"),
            (["-F", "127.0.0.1:1", "-L", "53::53"], "empty target host"),
            (["-F", "127.0.0.1:1", "-L", "a:b:53:1.1.1.1:53"], "invalid source address"),
            (["-F", "127.0.0.1:1", "-bogus"], "flag provided but not defined"),
        ]:
            result = lib.wirez(*flags, "--", "true", check=False)
            self.assertNotEqual(result.returncode, 0, flags)
            self.assertIn(needle, result.stderr, flags)


class AllFlagsTest(lib.ContainerTest):
    def test_every_flag_is_accepted_together(self):
        proxy = lib.Socks5Server()
        flags = [
            "-F", proxy.addr, "-F", f"socks5h://{proxy.addr}",
            "-L", "53:127.0.0.1:5353/udp", "-L", "8080:127.0.0.1:80", "-B", "198.51.100.0/24",
            "-D", "192.0.2.53", "-D", "192.0.2.54:5353",
            "-6", "-nat64", "64:ff9b::/96", "-hostname", "box",
            "-connect-timeout", "7s", "-tcp-timeout", "1m", "-udp-timeout", "30s",
            "-v", "-v", "-q", "-uid", str(lib.os.getuid()), "-gid", str(lib.os.getgid()),
        ]
        self.assertEqual(lib.in_container(flags, "id"), f"{lib.os.getuid()} {lib.os.getgid()}")


class HostnameTest(lib.ContainerTest):
    def test_hostname_inside_the_container(self):
        proxy = lib.Socks5Server()
        self.assertEqual(lib.in_container(["-F", proxy.addr], "hostname"), "wirez")
        self.assertEqual(lib.in_container(["-F", proxy.addr, "-hostname", "box"], "hostname"), "box")
        hosts = lib.in_container(["-F", proxy.addr, "-hostname", "box"], "file", "/etc/hosts")
        self.assertIn("127.0.0.1 box box.localdomain\n", hosts)

    def test_container_setup_failure_is_reported(self):
        # a hostname the kernel refuses makes the container half die before
        # it hands its network descriptors over
        proxy = lib.Socks5Server()
        result = lib.in_container(["-F", proxy.addr, "-hostname", "x" * 300], "id", check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("child exited before sending network file descriptors", result.stderr)


class LoggingTest(lib.ContainerTest):
    def test_quiet_suppresses_logs_and_verbose_shows_them(self):
        proxy = lib.Socks5Server(backend=lib.closed_tcp_port())
        quiet = lib.in_container(["-F", proxy.addr, "-q"], "refused", "192.0.2.1:9", check=False)
        self.assertEqual(quiet.stdout, "refused")
        self.assertEqual(quiet.stderr, "")
        verbose = lib.in_container(["-F", proxy.addr, "-v"], "refused", "192.0.2.1:9", check=False)
        self.assertEqual(verbose.stdout, "refused")
        self.assertIn("level=DEBUG", verbose.stderr)
        self.assertIn("tcp: dial failed", verbose.stderr)
        chatty = lib.in_container(["-F", proxy.addr, "-v", "-v"], "refused", "192.0.2.1:9", check=False)
        self.assertEqual(chatty.stdout, "refused")
        self.assertIn("level=DEBUG", chatty.stderr)


class UdpTimeoutTest(lib.ContainerTest):
    def test_udp_timeout_ends_idle_flows(self):
        echo = lib.UdpEchoServer()
        proxy = lib.Socks5Server(udp_backend=echo.addr)
        flags = ["-F", proxy.addr, "-udp-timeout", "300ms"]
        # two exchanges with a pause longer than the timeout in between
        out = lib.in_container(flags, "udp-twice", "192.0.2.1:5353", "1")
        self.assertEqual(out, "ping? ping?")
        self.assertEqual(proxy.associations, 2)

    def test_udp_flows_survive_a_short_pause_by_default(self):
        echo = lib.UdpEchoServer()
        proxy = lib.Socks5Server(udp_backend=echo.addr)
        out = lib.in_container(["-F", proxy.addr], "udp-twice", "192.0.2.1:5353", "1")
        self.assertEqual(out, "ping? ping?")
        self.assertEqual(proxy.associations, 1)


if __name__ == "__main__":
    unittest.main()
