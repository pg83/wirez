"""The program's surroundings survive the container: a terminal, stdin,
the working directory, the environment."""

import os
import subprocess
import sys
import unittest

import lib


class EnvironmentTest(lib.ContainerTest):
    def setUp(self):
        self.proxy = lib.Socks5Server()
        self.flags = ["-F", self.proxy.addr]

    def test_terminal_is_passed_through(self):
        master, slave = os.openpty()
        try:
            proc = subprocess.Popen(
                [str(lib.WIREZ), *self.flags, "--", sys.executable, "-c",
                 "import sys; print(sys.stdin.isatty(), sys.stdout.isatty())"],
                stdin=slave, stdout=slave, stderr=subprocess.DEVNULL,
            )
            os.close(slave)
            out = b""
            while True:
                try:
                    chunk = os.read(master, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                out += chunk
            proc.wait(lib.TIMEOUT)
        finally:
            os.close(master)
        self.assertEqual(out.decode().strip(), "True True")

    def test_stdin_is_passed_through(self):
        result = lib.in_container_run(
            self.flags, [sys.executable, "-c", "import sys; sys.stdout.write(sys.stdin.read())"], input=b"piped data",
        )
        self.assertEqual(result.stdout, "piped data")

    def test_working_directory_and_environment(self):
        result = lib.in_container_run(
            self.flags, [sys.executable, "-c", "import os; print(os.getcwd(), os.environ['WIREZ_TEST_MARK'])"],
            env=lib.wirez_env({"WIREZ_TEST_MARK": "kept"}),
        )
        self.assertEqual(result.stdout, f"{os.getcwd()} kept\n")


if __name__ == "__main__":
    unittest.main()
