"""OpenSSH through the proxy: the server talks first (its banner must not be
lost in the CONNECT reply), commands run, long-running commands survive, scp
moves files, and ssh -D is a real SOCKS5 proxy wirez can use."""

import os
import shutil
import sys
import unittest

import lib

lib.reexec_in_netns(setup=lib.WORKLOAD_NETNS_SETUP)


class SshTest(lib.WorkloadTest):
    def setUp(self):
        super().setUp()
        lib.require_tools(self, "ssh", "sshd", "ssh-keygen", "scp")
        self.env = lib.wirez_env(lib.nss_env(self.dir))
        for name in ("host_key", "user_key"):
            lib.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", self.dir / name], env=self.env)
        authorized = self.dir / "authorized_keys"
        authorized.write_text((self.dir / "user_key.pub").read_text())
        self.port = lib.free_port()
        (self.dir / "sshd_config").write_text(
            f"Port {self.port}\nListenAddress {lib.WORKLOAD_IPV4}\nHostKey {self.dir}/host_key\n"
            "PidFile none\nUsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n"
            f"PubkeyAuthentication yes\nAuthorizedKeysFile {authorized}\nStrictModes no\n"
            "Subsystem sftp internal-sftp\nLogLevel ERROR\n"
        )
        self.sshd = self.daemon([shutil.which("sshd"), "-D", "-e", "-f", self.dir / "sshd_config"], env=self.env)
        lib.wait_port(lib.WORKLOAD_IPV4, self.port, daemon=self.sshd)
        self.ssh_args = [
            "-p", str(self.port), "-i", str(self.dir / "user_key"), "-F", "/dev/null",
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "BatchMode=yes", "-o", "LogLevel=ERROR",
        ]
        self.target = f"{lib.user_name()}@{lib.WORKLOAD_IPV4}"

    def ssh(self, *command):
        result = lib.in_container_run(self.flags, ["ssh", *self.ssh_args, self.target, *command], env=self.env, check=False)
        if result.returncode != 0:
            self.fail(f"ssh exited with {result.returncode}: {result.stderr}\nsshd: {self.sshd.output()}")
        return result.stdout

    def test_command(self):
        self.assertEqual(self.ssh("echo", "ok"), "ok\n")
        self.assertEqual(self.proxy.connects, [f"{lib.WORKLOAD_IPV4}:{self.port}"])

    def test_long_running_command(self):
        self.assertEqual(self.ssh("sleep 2; echo done"), "done\n")

    def test_scp_both_ways(self):
        big, sha = lib.random_file(self.dir, "big.bin", 4 << 20)
        scp_args = [a for a in self.ssh_args if a != "-p"]
        scp_args = ["-P", str(self.port), *[a for a in scp_args if a != str(self.port)]]
        lib.in_container_run(self.flags, ["scp", *scp_args, big, f"{self.target}:{self.dir}/uploaded.bin"], env=self.env)
        self.assertEqual(lib.sha256_file(self.dir / "uploaded.bin"), sha)
        lib.in_container_run(self.flags, ["scp", *scp_args, f"{self.target}:{self.dir}/uploaded.bin", self.dir / "back.bin"], env=self.env)
        self.assertEqual(lib.sha256_file(self.dir / "back.bin"), sha)

    def test_dynamic_forwarding_is_a_socks5_proxy_for_wirez(self):
        # ssh -D on the host side is a real SOCKS5 server (TCP only); wirez uses it
        socks_port = lib.free_port("127.0.0.1")
        forwarder = self.daemon(
            ["ssh", *self.ssh_args, "-N", "-D", f"127.0.0.1:{socks_port}", self.target], env=self.env,
        )
        lib.wait_port("127.0.0.1", socks_port, daemon=forwarder)
        (self.dir / "index.html").write_text("via ssh -D\n")
        http_port = lib.free_port()
        self.daemon([sys.executable, lib.HTTPD, lib.WORKLOAD_IPV4, http_port, self.dir])
        lib.wait_port(lib.WORKLOAD_IPV4, http_port)
        out = lib.in_container_run(
            ["-F", f"127.0.0.1:{socks_port}"],
            ["curl", "-sS", "--max-time", "30", f"http://{lib.WORKLOAD_IPV4}:{http_port}/index.html"],
        ).stdout
        self.assertEqual(out, "via ssh -D\n", forwarder.output())


if __name__ == "__main__":
    unittest.main()
