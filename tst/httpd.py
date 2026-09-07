#!/usr/bin/env python3
"""A small HTTP/1.1 server for the workload tests: GET serves files from a
directory, POST /upload answers with the SHA-256 of the body, and connections
are kept alive so one curl can fetch several URLs over one connection.

usage: httpd.py HOST PORT DIRECTORY"""

import hashlib
import sys
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer


class Handler(SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_POST(self):
        if self.path != "/upload":
            self.send_error(404)
            return
        digest = hashlib.sha256()
        remaining = int(self.headers.get("Content-Length", "0"))
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 1 << 20))
            if not chunk:
                break
            digest.update(chunk)
            remaining -= len(chunk)
        body = digest.hexdigest().encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    host, port, directory = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    server = ThreadingHTTPServer((host, port), partial(Handler, directory=directory))
    server.daemon_threads = True
    server.serve_forever()
