"""A statically linked program, the case LD_PRELOAD proxifiers cannot handle:
busybox wget through the proxy."""

import struct
import sys
import unittest

import lib

lib.reexec_in_netns(setup=lib.WORKLOAD_NETNS_SETUP)


def is_static(path):
    """True when the ELF at path has no PT_INTERP (no dynamic loader)."""
    with open(path, "rb") as stream:
        header = stream.read(64)
        if header[:4] != b"\x7fELF" or header[4] != 2:
            return False
        phoff, = struct.unpack_from("<Q", header, 32)
        phentsize, phnum = struct.unpack_from("<HH", header, 54)
        stream.seek(phoff)
        for _ in range(phnum):
            entry = stream.read(phentsize)
            if struct.unpack_from("<I", entry, 0)[0] == 3:
                return False
    return True


class StaticBinaryTest(lib.WorkloadTest):
    def test_busybox_wget(self):
        busybox = lib.static_busybox()
        if busybox is None:
            lib.require_tools(self, "busybox")
        if not is_static(busybox):
            problem = f"{busybox} is dynamically linked"
            if lib.REQUIRED:
                self.fail(problem)
            lib.skip(problem)
        (self.dir / "index.html").write_text("fetched by a static binary\n")
        port = lib.free_port()
        self.daemon([sys.executable, lib.HTTPD, lib.WORKLOAD_IPV4, port, self.dir])
        lib.wait_port(lib.WORKLOAD_IPV4, port)
        out = lib.in_container_run(self.flags, [busybox, "wget", "-q", "-O", "-", f"http://{lib.WORKLOAD_IPV4}:{port}/index.html"]).stdout
        self.assertEqual(out, "fetched by a static binary\n")
        self.assertEqual(self.proxy.connects, [f"{lib.WORKLOAD_IPV4}:{port}"])


if __name__ == "__main__":
    unittest.main()
