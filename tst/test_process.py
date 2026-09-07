"""Process plumbing: exit codes, uid/gid, descriptors, temp dirs, the
container dying with wirez, and /etc/hosts."""

import os
import subprocess
import sys
import time
import unittest

import lib


class ProcessTest(lib.ContainerTest):
    def setUp(self):
        self.proxy = lib.Socks5Server()
        self.flags = ["-F", self.proxy.addr]

    def test_exit_code_is_propagated(self):
        result = lib.in_container(self.flags, "exit", "3", check=False)
        self.assertEqual(result.returncode, 3)

    def test_signal_death_is_reported_as_128_plus_signal(self):
        result = lib.in_container(self.flags, "signal", "9", check=False)
        self.assertEqual(result.returncode, 137)

    def test_uid_and_gid(self):
        self.assertEqual(lib.in_container([*self.flags, "-uid", "12345", "-gid", "12345"], "id"), "12345 12345")

    def test_no_descriptor_leaks_into_the_program(self):
        baseline = subprocess.run([sys.executable, lib.CLIENT, "fds"], capture_output=True, text=True, check=True)
        inside = lib.in_container(self.flags, "fds")
        self.assertEqual(len(inside.split()), len(baseline.stdout.split()), f"inside {inside!r}, outside {baseline.stdout!r}")

    def test_temp_dirs_are_cleaned_up(self):
        before = lib.wirez_temp_dirs()
        lib.in_container(self.flags, "id")
        self.assertEqual(lib.wirez_temp_dirs(), before)

    def test_container_dies_with_wirez(self):
        proc = subprocess.Popen(
            [str(lib.WIREZ), *self.flags, "--", sys.executable, lib.CLIENT, "sleep", "30"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        )
        try:
            pid = int(proc.stdout.readline())
        finally:
            proc.kill()
            proc.wait()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                with open(f"/proc/{pid}/stat") as stat:
                    state = stat.read().rsplit(")", 1)[1].split()[0]
            except FileNotFoundError:
                return
            if state == "Z":
                return
            time.sleep(0.1)
        self.fail(f"program {pid} outlived wirez")

    def test_hosts_keeps_host_entries_and_adds_localhost(self):
        out = lib.in_container(self.flags, "file", "/etc/hosts")
        self.assertIn("127.0.0.1 localhost\n", out)
        self.assertIn("10.1.1.2 localhost\n", out)
        self.assertIn("127.0.0.1 wirez wirez.localdomain\n", out)
        with open("/etc/hosts") as host:
            for line in host:
                if line.split() and not line.lstrip().startswith("#"):
                    self.assertIn(line.rstrip("\n"), out)
                    break


if __name__ == "__main__":
    unittest.main()
