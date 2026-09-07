"""git clone through the proxy over ssh and over HTTP."""

import shutil
import sys
import unittest

import lib

lib.reexec_in_netns(setup=lib.WORKLOAD_NETNS_SETUP)


class GitTest(lib.WorkloadTest):
    def setUp(self):
        super().setUp()
        lib.require_tools(self, "git")
        self.git_env = lib.wirez_env({
            "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "test@example", 
            "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "test@example",
            "HOME": str(self.dir),
        })
        work = self.dir / "work"
        work.mkdir()
        (work / "README").write_text("cloned through wirez\n")
        for argv in (["init", "-q", "-b", "main"], ["add", "README"], ["commit", "-q", "-m", "init"]):
            lib.run(["git", "-C", work, *argv], env=self.git_env)
        self.repo = self.dir / "repo.git"
        lib.run(["git", "clone", "-q", "--bare", work, self.repo], env=self.git_env)
        lib.run(["git", "-C", self.repo, "update-server-info"], env=self.git_env)

    def assert_clone(self, url, env, extra_flags=()):
        target = self.dir / "clone"
        lib.in_container_run([*self.flags, *extra_flags], ["git", "clone", "-q", url, target], env=env)
        self.assertEqual((target / "README").read_text(), "cloned through wirez\n")

    def test_clone_over_http(self):
        port = lib.free_port()
        self.daemon([sys.executable, lib.HTTPD, lib.WORKLOAD_IPV4, port, self.dir])
        lib.wait_port(lib.WORKLOAD_IPV4, port)
        self.assert_clone(f"http://{lib.WORKLOAD_IPV4}:{port}/repo.git", self.git_env)
        self.assertEqual(self.proxy.connects, [f"{lib.WORKLOAD_IPV4}:{port}"])

    def test_clone_over_ssh(self):
        lib.require_tools(self, "ssh", "sshd", "ssh-keygen")
        env = lib.wirez_env({**self.git_env, **lib.nss_env(self.dir)})
        for name in ("host_key", "user_key"):
            lib.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", self.dir / name], env=env)
        (self.dir / "authorized_keys").write_text((self.dir / "user_key.pub").read_text())
        port = lib.free_port()
        (self.dir / "sshd_config").write_text(
            f"Port {port}\nListenAddress {lib.WORKLOAD_IPV4}\nHostKey {self.dir}/host_key\n"
            "PidFile none\nUsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n"
            f"PubkeyAuthentication yes\nAuthorizedKeysFile {self.dir}/authorized_keys\nStrictModes no\nLogLevel ERROR\n"
        )
        sshd = self.daemon([shutil.which("sshd"), "-D", "-e", "-f", self.dir / "sshd_config"], env=env)
        lib.wait_port(lib.WORKLOAD_IPV4, port, daemon=sshd)
        env["GIT_SSH_COMMAND"] = (
            f"ssh -p {port} -i {self.dir}/user_key -F /dev/null -o StrictHostKeyChecking=no "
            "-o UserKnownHostsFile=/dev/null -o BatchMode=yes -o LogLevel=ERROR"
        )
        self.assert_clone(f"{lib.user_name()}@{lib.WORKLOAD_IPV4}:{self.repo}", env)
        self.assertEqual(self.proxy.connects, [f"{lib.WORKLOAD_IPV4}:{port}"])


if __name__ == "__main__":
    unittest.main()
