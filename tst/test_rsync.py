"""rsync over ssh through the proxy, a tree in both directions."""

import filecmp
import os
import unittest

import lib

lib.reexec_in_netns(setup=lib.WORKLOAD_NETNS_SETUP)


def make_tree(root):
    root.mkdir()
    for index in range(20):
        sub = root / f"dir{index % 4}"
        sub.mkdir(exist_ok=True)
        (sub / f"file{index}.bin").write_bytes(os.urandom(1 << 16 if index % 5 else 1 << 20))
    (root / "empty").mkdir()
    (root / "note.txt").write_text("rsync through wirez\n")


def assert_same_tree(test, a, b):
    comparison = filecmp.dircmp(a, b)
    test.assertEqual((comparison.left_only, comparison.right_only, comparison.diff_files), ([], [], []))
    for sub in comparison.subdirs:
        assert_same_tree(test, a / sub, b / sub)


class RsyncTest(lib.WorkloadTest):
    def setUp(self):
        super().setUp()
        lib.require_tools(self, "rsync")
        self.sshd = lib.SshServer(self, self.dir)
        self.source = self.dir / "source"
        make_tree(self.source)

    def rsync(self, src, dst):
        lib.in_container_run(
            self.flags, ["rsync", "-a", "--checksum", "-e", self.sshd.ssh_command, src, dst], env=self.sshd.env, timeout=120,
        )

    def test_push_then_pull(self):
        self.rsync(f"{self.source}/", f"{self.sshd.target}:{self.dir}/pushed/")
        assert_same_tree(self, self.source, self.dir / "pushed")
        # a second pass over an identical tree is a no-op, an update is not
        (self.source / "note.txt").write_text("changed\n")
        self.rsync(f"{self.source}/", f"{self.sshd.target}:{self.dir}/pushed/")
        self.assertEqual((self.dir / "pushed" / "note.txt").read_text(), "changed\n")
        self.rsync(f"{self.sshd.target}:{self.dir}/pushed/", f"{self.dir}/pulled/")
        assert_same_tree(self, self.source, self.dir / "pulled")
        self.assertEqual(len(self.proxy.connects), 3)


if __name__ == "__main__":
    unittest.main()
