"""OpenSSH through the proxy: the server talks first (its banner must not be
lost in the CONNECT reply), commands run, long-running commands survive, scp
moves files, and ssh -D is a real SOCKS5 proxy wirez can use."""

import sys
import unittest

import lib

lib.reexec_in_netns(setup=lib.WORKLOAD_NETNS_SETUP)


class SshTest(lib.WorkloadTest):
    def setUp(self):
        super().setUp()
        self.sshd = lib.SshServer(self, self.dir)

    def ssh(self, *command):
        result = lib.in_container_run(
            self.flags, ["ssh", *self.sshd.ssh_args, self.sshd.target, *command], env=self.sshd.env, check=False,
        )
        if result.returncode != 0:
            self.fail(f"ssh exited with {result.returncode}: {result.stderr}\nsshd: {self.sshd.daemon.output()}")
        return result.stdout

    def test_command(self):
        self.assertEqual(self.ssh("echo", "ok"), "ok\n")
        self.assertEqual(self.proxy.connects, [f"{lib.WORKLOAD_IPV4}:{self.sshd.port}"])

    def test_long_running_command(self):
        self.assertEqual(self.ssh("sleep 2; echo done"), "done\n")

    def test_scp_both_ways(self):
        big, sha = lib.random_file(self.dir, "big.bin", 4 << 20)
        lib.in_container_run(self.flags, ["scp", *self.sshd.scp_args, big, f"{self.sshd.target}:{self.dir}/uploaded.bin"], env=self.sshd.env)
        self.assertEqual(lib.sha256_file(self.dir / "uploaded.bin"), sha)
        lib.in_container_run(self.flags, ["scp", *self.sshd.scp_args, f"{self.sshd.target}:{self.dir}/uploaded.bin", self.dir / "back.bin"], env=self.sshd.env)
        self.assertEqual(lib.sha256_file(self.dir / "back.bin"), sha)

    def test_dynamic_forwarding_is_a_socks5_proxy_for_wirez(self):
        # ssh -D on the host side is a real SOCKS5 server (TCP only); wirez uses it
        socks_port = lib.free_port("127.0.0.1")
        forwarder = self.daemon(
            ["ssh", *self.sshd.ssh_args, "-N", "-D", f"127.0.0.1:{socks_port}", self.sshd.target], env=self.sshd.env,
        )
        lib.wait_port("127.0.0.1", socks_port, daemon=forwarder)
        (self.dir / "index.html").write_text("via ssh -D\n")
        http_port = lib.free_port()
        httpd = self.daemon([sys.executable, lib.HTTPD, lib.WORKLOAD_IPV4, http_port, self.dir])
        lib.wait_port(lib.WORKLOAD_IPV4, http_port, daemon=httpd)
        out = lib.in_container_run(
            ["-F", f"127.0.0.1:{socks_port}"],
            ["curl", "-sS", "--max-time", "30", f"http://{lib.WORKLOAD_IPV4}:{http_port}/index.html"],
        ).stdout
        self.assertEqual(out, "via ssh -D\n", forwarder.output())


if __name__ == "__main__":
    unittest.main()
