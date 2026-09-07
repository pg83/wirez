"""A WebSocket connection with a long pause between frames stays up."""

import select
import subprocess
import time
import unittest

import lib

lib.reexec_in_netns(setup=lib.WORKLOAD_NETNS_SETUP)


def read_line(stream, timeout):
    ready, _, _ = select.select([stream], [], [], timeout)
    if not ready:
        raise TimeoutError("no frame within the timeout")
    return stream.readline().decode()


class WebSocketTest(lib.WorkloadTest):
    def setUp(self):
        super().setUp()
        lib.require_tools(self, "websocat")
        self.port = lib.free_port()
        self.server = self.daemon(["websocat", "-E", "-t", f"ws-l:{lib.WORKLOAD_IPV4}:{self.port}", "mirror:"])
        lib.wait_port(lib.WORKLOAD_IPV4, self.port, daemon=self.server)

    def test_frames_around_a_long_pause(self):
        client = subprocess.Popen(
            [str(lib.WIREZ), *self.flags, "--", "websocat", "-E", "-t", f"ws://{lib.WORKLOAD_IPV4}:{self.port}"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            client.stdin.write(b"first frame\n")
            client.stdin.flush()
            self.assertEqual(read_line(client.stdout, lib.TIMEOUT), "first frame\n")
            time.sleep(5)
            client.stdin.write(b"second frame\n")
            client.stdin.flush()
            self.assertEqual(read_line(client.stdout, lib.TIMEOUT), "second frame\n")
            client.stdin.close()
            self.assertEqual(client.wait(lib.TIMEOUT), 0, client.stderr.read().decode())
        finally:
            client.kill()
            client.wait()
            for stream in (client.stdout, client.stderr):
                stream.close()
        self.assertEqual(self.proxy.connects, [f"{lib.WORKLOAD_IPV4}:{self.port}"])


if __name__ == "__main__":
    unittest.main()
