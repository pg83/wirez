"""git clone through the proxy over ssh and over HTTP."""

import sys
import unittest

import lib

lib.reexec_in_netns(setup=lib.WORKLOAD_NETNS_SETUP)


class GitTest(lib.WorkloadTest):
    def setUp(self):
        super().setUp()
        lib.require_tools(self, "git")
        self.git_env = {
            "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "test@example",
            "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "test@example",
            "HOME": str(self.dir),
        }
        env = lib.wirez_env(self.git_env)
        work = self.dir / "work"
        work.mkdir()
        (work / "README").write_text("cloned through wirez\n")
        for argv in (["init", "-q", "-b", "main"], ["add", "README"], ["commit", "-q", "-m", "init"]):
            lib.run(["git", "-C", work, *argv], env=env)
        self.repo = self.dir / "repo.git"
        lib.run(["git", "clone", "-q", "--bare", work, self.repo], env=env)
        lib.run(["git", "-C", self.repo, "update-server-info"], env=env)

    def assert_clone(self, url, env):
        target = self.dir / "clone"
        lib.in_container_run(self.flags, ["git", "clone", "-q", url, target], env=env)
        self.assertEqual((target / "README").read_text(), "cloned through wirez\n")

    def test_clone_over_http(self):
        port = lib.free_port()
        httpd = self.daemon([sys.executable, lib.HTTPD, lib.WORKLOAD_IPV4, port, self.dir])
        lib.wait_port(lib.WORKLOAD_IPV4, port, daemon=httpd)
        self.assert_clone(f"http://{lib.WORKLOAD_IPV4}:{port}/repo.git", lib.wirez_env(self.git_env))
        self.assertEqual(self.proxy.connects, [f"{lib.WORKLOAD_IPV4}:{port}"])

    def test_clone_over_ssh(self):
        sshd = lib.SshServer(self, self.dir, extra_env=self.git_env)
        env = dict(sshd.env, GIT_SSH_COMMAND=sshd.ssh_command)
        self.assert_clone(f"{sshd.target}:{self.repo}", env)
        self.assertEqual(self.proxy.connects, [f"{lib.WORKLOAD_IPV4}:{sshd.port}"])


if __name__ == "__main__":
    unittest.main()
