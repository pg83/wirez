"""Proxies and relays that break the protocol: wirez refuses the connection
and says why, and a UDP flow survives junk from the relay."""

import unittest

import lib


class BadSocks5ProxyTest(lib.ContainerTest):
    def assert_refused(self, proxy, message, flags=()):
        result = lib.in_container(["-F", proxy.addr, "-v", *flags], "refused", "192.0.2.1:80", check=False)
        self.assertEqual(result.stdout, "refused")
        self.assertIn(message, result.stderr)

    def test_wrong_version(self):
        self.assert_refused(lib.Socks5Server(misbehave="bad_version"), "socks5: bad version 4")

    def test_no_acceptable_method(self):
        self.assert_refused(lib.Socks5Server(misbehave="no_method"), "no acceptable authentication method")

    def test_hang_up_after_method_selection(self):
        self.assert_refused(lib.Socks5Server(misbehave="close_after_methods"), "EOF")

    def test_reply_with_wrong_version(self):
        self.assert_refused(lib.Socks5Server(misbehave="reply_bad_version"), "socks5: bad version 4")

    def test_reply_code_outside_the_rfc(self):
        self.assert_refused(lib.Socks5Server(misbehave="reply_unknown_code"), "socks5: reply code 66")

    def test_reply_with_unknown_address_type(self):
        self.assert_refused(lib.Socks5Server(misbehave="reply_bad_atyp"), "socks5: bad address type 9")

    def test_credentials_too_long_for_the_protocol(self):
        proxy = lib.Socks5Server(user="alice", password="s3cret")
        result = lib.in_container(["-F", f"socks5://{'a' * 256}:x@{proxy.addr}", "-v"], "refused", "192.0.2.1:80", check=False)
        self.assertEqual(result.stdout, "refused")
        self.assertIn("longer than 255 bytes", result.stderr)


class BadUdpRelayTest(lib.ContainerTest):
    def assert_udp_works(self, proxy, flags=()):
        result = lib.in_container(["-F", proxy.addr, "-v", *flags], "udp", "192.0.2.1:5353", check=False)
        self.assertEqual(result.stdout, "ping?")
        return result.stderr

    def test_relay_named_by_domain(self):
        echo = lib.UdpEchoServer()
        self.assert_udp_works(lib.Socks5Server(udp_backend=echo.addr, misbehave="bind_domain"))

    def test_junk_datagrams_from_the_relay_are_dropped(self):
        echo = lib.UdpEchoServer()
        log = self.assert_udp_works(lib.Socks5Server(udp_backend=echo.addr, misbehave="udp_garbage"))
        self.assertIn("bad udp datagram from relay", log)

    def test_unsolicited_datagram_is_dropped(self):
        echo = lib.UdpEchoServer()
        self.assert_udp_works(lib.Socks5Server(udp_backend=echo.addr, misbehave="udp_unsolicited"))


class BadHttpProxyTest(lib.ContainerTest):
    def assert_refused(self, proxy, message):
        result = lib.in_container(["-F", f"http://{proxy.addr}", "-v"], "refused", "192.0.2.1:80", check=False)
        self.assertEqual(result.stdout, "refused")
        self.assertIn(message, result.stderr)

    def test_malformed_status_line(self):
        self.assert_refused(lib.HttpConnectProxy(misbehave="malformed_status"), "malformed response")

    def test_hang_up_without_answering(self):
        self.assert_refused(lib.HttpConnectProxy(misbehave="close"), "EOF")


if __name__ == "__main__":
    unittest.main()
