"""Shared helpers for the wirez integration tests.

Every test drives the real wirez binary (WIREZ_TEST_BINARY) with fake
servers on loopback playing the proxy, the DNS upstream and the destinations,
and runs tst/client.py inside the container to generate traffic.
"""

import base64
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

import dnswire

WIREZ = Path(os.environ["WIREZ_TEST_BINARY"]).resolve()
CLIENT = str(Path(__file__).resolve().with_name("client.py"))
REQUIRED = bool(os.environ.get("WIREZ_TEST_CONTAINER_REQUIRED"))
TIMEOUT = 60


def container_support_problem():
    """Why the container cannot be created here, or None."""
    try:
        os.close(os.open("/dev/net/tun", os.O_RDWR))
    except OSError as error:
        return f"no TUN device: {error}"
    if os.geteuid() != 0:
        result = subprocess.run(
            ["unshare", "-r", "-n", "true"], capture_output=True, text=True, check=False,
        )
        if result.returncode != 0:
            return f"no unprivileged user namespaces: {result.stderr.strip()}"
    return None


class ContainerTest(unittest.TestCase):
    """Base for tests that need the container; skips where it is impossible
    unless WIREZ_TEST_CONTAINER_REQUIRED is set, which CI does so that a
    silently skipped test cannot pass for a green run."""

    @classmethod
    def setUpClass(cls):
        problem = container_support_problem()
        if problem is None:
            return
        if REQUIRED:
            raise AssertionError(problem)
        raise unittest.SkipTest(problem)


def wirez(*args, timeout=TIMEOUT, check=True):
    argv = [str(WIREZ), *map(str, args)]
    # bytes, not text mode: text mode would fold the \r\n of protocol banners
    raw = subprocess.run(
        argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False,
    )
    result = subprocess.CompletedProcess(
        raw.args, raw.returncode, raw.stdout.decode(errors="replace"), raw.stderr.decode(errors="replace"),
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"wirez exited with {result.returncode}: {argv!r}\n"
            f"--- stdout ---\n{result.stdout}"
            f"--- stderr ---\n{result.stderr}"
        )
    return result


def in_container(flags, mode, *args, timeout=TIMEOUT, check=True):
    """Runs tst/client.py inside a wirez container started with flags and
    returns its stdout (or the whole result when check is False)."""
    result = wirez(*flags, "--", sys.executable, CLIENT, mode, *args, timeout=timeout, check=check)
    return result.stdout if check else result


def host_ip():
    """An IPv4 address of this host that the container will route through the
    TUN: not loopback and not in the TUN subnet itself (the test host may be a
    wirez container too). None when there is no such address."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.connect(("192.0.2.1", 9))
            ip = sock.getsockname()[0]
        except OSError:
            return None
    if ip.startswith("127.") or ip.startswith("10.1.1."):
        return None
    return ip


def wirez_temp_dirs():
    return sorted(Path(tempfile.gettempdir()).glob("wirez-*"))


def recv_exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError("connection closed")
        data += chunk
    return data


def relay(a, b):
    """Copies bytes both ways between two TCP sockets, forwarding half-closes."""
    def pump(src, dst):
        try:
            while True:
                chunk = src.recv(65536)
                if not chunk:
                    break
                dst.sendall(chunk)
        except OSError:
            pass
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    threads = [threading.Thread(target=pump, args=pair, daemon=True) for pair in ((a, b), (b, a))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()


class TcpServer:
    """A loopback TCP listener whose handle() runs per connection in a thread."""

    def __init__(self, host="127.0.0.1"):
        self.sock = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.host = host
        threading.Thread(target=self._serve, daemon=True).start()

    @property
    def addr(self):
        host = "127.0.0.1" if self.host == "0.0.0.0" else self.host
        return f"[{host}]:{self.port}" if ":" in host else f"{host}:{self.port}"

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle_and_close, args=(conn,), daemon=True).start()

    def _handle_and_close(self, conn):
        conn.settimeout(TIMEOUT)
        try:
            self.handle(conn)
        except (EOFError, OSError):
            pass  # the client went away, which some tests provoke on purpose
        finally:
            conn.close()

    def handle(self, conn):
        raise NotImplementedError

    def close(self):
        self.sock.close()


class EchoServer(TcpServer):
    """Sends an optional greeting first (SSH and SMTP servers talk first) and
    answers 'echo:' plus everything it read once the client half-closed."""

    def __init__(self, greeting=b"", host="127.0.0.1"):
        self.greeting = greeting
        super().__init__(host)

    def handle(self, conn):
        if self.greeting:
            conn.sendall(self.greeting)
        data = b""
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                break
            data += chunk
        conn.sendall(b"echo:" + data)


class SilentServer(TcpServer):
    """Accepts and keeps the connection open without saying anything."""

    def handle(self, conn):
        try:
            while conn.recv(65536):
                pass
        except OSError:
            pass


class UdpEchoServer:
    def __init__(self, host="127.0.0.1"):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host, 0))
        self.port = self.sock.getsockname()[1]
        self.addr = f"127.0.0.1:{self.port}"
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                data, sender = self.sock.recvfrom(65536)
            except OSError:
                return
            self.sock.sendto(data, sender)

    def close(self):
        self.sock.close()


# --- SOCKS5 ---------------------------------------------------------------

def socks_addr_bytes(host, port):
    try:
        return b"\x01" + socket.inet_pton(socket.AF_INET, host) + struct.pack("!H", port)
    except OSError:
        pass
    try:
        return b"\x04" + socket.inet_pton(socket.AF_INET6, host) + struct.pack("!H", port)
    except OSError:
        pass
    return b"\x03" + bytes([len(host)]) + host.encode() + struct.pack("!H", port)


def socks_read_addr(read):
    """read(n) returns exactly n bytes; returns (host, port)."""
    atyp = read(1)[0]
    if atyp == 1:
        host = socket.inet_ntop(socket.AF_INET, read(4))
    elif atyp == 4:
        host = socket.inet_ntop(socket.AF_INET6, read(16))
    elif atyp == 3:
        host = read(read(1)[0]).decode()
    else:
        raise ValueError(f"bad address type {atyp}")
    return host, struct.unpack("!H", read(2))[0]


def socks_parse_udp(datagram):
    """Returns (host, port, payload) of a SOCKS5 UDP datagram."""
    offset = [3]

    def read(n):
        chunk = datagram[offset[0]:offset[0] + n]
        offset[0] += n
        return chunk

    host, port = socks_read_addr(read)
    return host, port, datagram[offset[0]:]


def socks_udp_datagram(host, port, payload):
    return b"\0\0\0" + socks_addr_bytes(host, port) + payload


def format_addr(host, port):
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


class Socks5Server(TcpServer):
    """A SOCKS5 proxy for tests. CONNECT relays to the requested destination
    (or to backend) and records it; UDP ASSOCIATE replies with an unspecified
    bind address, as some real proxies do, and relays datagrams to their
    destination (or to udp_backend) with the requested address in replies."""

    def __init__(self, backend=None, udp_backend=None, user=None, password=None, banner=b""):
        self.backend = backend
        self.udp_backend = udp_backend
        self.user = user
        self.password = password
        self.banner = banner
        self.lock = threading.Lock()
        self.connects = []
        self.associations = 0
        super().__init__()

    def handle(self, conn):
        read = lambda n: recv_exact(conn, n)
        version, count = read(2)
        if version != 5:
            return
        read(count)
        if self.user is None:
            conn.sendall(b"\x05\x00")
        else:
            conn.sendall(b"\x05\x02")
            _, ulen = read(2)
            user = read(ulen).decode()
            pass_ = read(read(1)[0]).decode()
            if (user, pass_) != (self.user, self.password):
                conn.sendall(b"\x01\x01")
                return
            conn.sendall(b"\x01\x00")
        _, cmd, _ = read(3)
        host, port = socks_read_addr(read)
        if cmd == 1:
            self.connect(conn, host, port)
        elif cmd == 3:
            self.associate(conn)
        else:
            conn.sendall(b"\x05\x07\x00" + socks_addr_bytes("0.0.0.0", 0))

    def connect(self, conn, host, port):
        with self.lock:
            self.connects.append(format_addr(host, port))
        target = self.backend or format_addr(host, port)
        thost, _, tport = target.rpartition(":")
        try:
            dst = socket.create_connection((thost.strip("[]"), int(tport)), timeout=TIMEOUT)
        except OSError:
            conn.sendall(b"\x05\x05\x00" + socks_addr_bytes("0.0.0.0", 0))
            return
        with dst:
            # a proxy may put the destination's first bytes into the same
            # segment as its reply; a correct client must not lose them
            conn.sendall(b"\x05\x00\x00" + socks_addr_bytes("0.0.0.0", 0) + self.banner)
            conn.settimeout(None)
            dst.settimeout(None)
            relay(conn, dst)

    def associate(self, control):
        relay_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        relay_sock.bind(("127.0.0.1", 0))
        out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        out.bind(("127.0.0.1", 0))
        with self.lock:
            self.associations += 1
        state = {"client": None, "requested": {}}
        lock = threading.Lock()

        def inbound():
            while True:
                try:
                    data, sender = relay_sock.recvfrom(65536)
                except OSError:
                    return
                host, port, payload = socks_parse_udp(data)
                with lock:
                    state["client"] = sender
                    # the echo backend sends the payload back unchanged, so
                    # it identifies the request the reply belongs to
                    state["requested"][payload] = (host, port)
                target = self.udp_backend or format_addr(host, port)
                thost, _, tport = target.rpartition(":")
                out.sendto(payload, (thost.strip("[]"), int(tport)))

        def outbound():
            while True:
                try:
                    data, sender = out.recvfrom(65536)
                except OSError:
                    return
                with lock:
                    client = state["client"]
                    host, port = state["requested"].get(data, sender)
                if self.udp_backend is None:
                    host, port = sender
                relay_sock.sendto(socks_udp_datagram(host, port, data), client)

        for target in (inbound, outbound):
            threading.Thread(target=target, daemon=True).start()
        control.sendall(b"\x05\x00\x00" + socks_addr_bytes("0.0.0.0", relay_sock.getsockname()[1]))
        control.settimeout(None)
        try:
            while control.recv(65536):
                pass
        except OSError:
            pass
        relay_sock.close()
        out.close()


# --- HTTP CONNECT -----------------------------------------------------------

class HttpConnectProxy(TcpServer):
    """An HTTP CONNECT proxy for tests, with optional Basic auth and the same
    banner trick as the SOCKS5 one."""

    def __init__(self, backend=None, user=None, password=None, banner=b""):
        self.backend = backend
        self.auth = None
        if user is not None:
            self.auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
        self.banner = banner
        self.lock = threading.Lock()
        self.connects = []
        super().__init__()

    def handle(self, conn):
        reader = conn.makefile("rb")
        request = reader.readline().decode().strip()
        headers = {}
        while True:
            line = reader.readline().decode().strip()
            if not line:
                break
            key, _, value = line.partition(":")
            headers[key.strip().lower()] = value.strip()
        method, target, _ = request.split(" ", 2)
        if method != "CONNECT":
            conn.sendall(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
            return
        if self.auth is not None and headers.get("proxy-authorization") != self.auth:
            conn.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
            return
        with self.lock:
            self.connects.append(target)
        thost, _, tport = (self.backend or target).rpartition(":")
        try:
            dst = socket.create_connection((thost.strip("[]"), int(tport)), timeout=TIMEOUT)
        except OSError:
            conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            return
        with dst:
            conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n" + self.banner)
            conn.settimeout(None)
            dst.settimeout(None)
            relay(conn, dst)


# --- DNS --------------------------------------------------------------------

class DnsServer:
    """A fake upstream on one loopback port over UDP and TCP. Names map to
    address lists; UDP answers carry the TC bit and no records when
    truncate_udp is set. Every query is recorded as (name, qtype, transport)."""

    def __init__(self, records, truncate_udp=False):
        self.records = records
        self.truncate_udp = truncate_udp
        self.lock = threading.Lock()
        self.queries = []
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", 0))
        self.port = self.udp.getsockname()[1]
        self.tcp = socket.socket(socket.AF_INET)
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp.bind(("127.0.0.1", self.port))
        self.tcp.listen(16)
        self.addr = f"127.0.0.1:{self.port}"
        threading.Thread(target=self._serve_udp, daemon=True).start()
        threading.Thread(target=self._serve_tcp, daemon=True).start()

    def answer(self, query, transport):
        _, _, name, qtype = dnswire.parse_question(query)
        with self.lock:
            self.queries.append((name, qtype, transport))
        ips = [ip for ip in self.records.get(name, [])
               if (":" in ip) == (qtype == dnswire.TYPE_AAAA)]
        if transport == "udp" and self.truncate_udp:
            return dnswire.build_answer(query, [], truncated=True)
        return dnswire.build_answer(query, ips)

    def _serve_udp(self):
        while True:
            try:
                query, sender = self.udp.recvfrom(65536)
            except OSError:
                return
            self.udp.sendto(self.answer(query, "udp"), sender)

    def _serve_tcp(self):
        while True:
            try:
                conn, _ = self.tcp.accept()
            except OSError:
                return
            threading.Thread(target=self._handle_tcp, args=(conn,), daemon=True).start()

    def _handle_tcp(self, conn):
        with conn:
            conn.settimeout(TIMEOUT)
            try:
                while True:
                    length = struct.unpack("!H", recv_exact(conn, 2))[0]
                    answer = self.answer(recv_exact(conn, length), "tcp")
                    conn.sendall(struct.pack("!H", len(answer)) + answer)
            except (EOFError, OSError):
                return

    def close(self):
        self.udp.close()
        self.tcp.close()


def closed_udp_port():
    """A loopback UDP address nobody listens on."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return f"127.0.0.1:{port}"


def unshare_available():
    return shutil.which("unshare") is not None


def closed_tcp_port():
    """A loopback TCP address nobody listens on."""
    sock = socket.socket(socket.AF_INET)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return f"127.0.0.1:{port}"
