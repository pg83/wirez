#!/usr/bin/env python3
"""The program the integration tests run inside the wirez container. Each mode
uses the network the way an ordinary application would and prints what it
saw; the test on the outside checks that against what its fake servers
recorded."""

import os
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import dnswire  # noqa: E402

TIMEOUT = 5.0


def split_host_port(address):
    host, _, port = address.rpartition(":")
    return host.strip("[]"), int(port)


def connect(address):
    host, port = split_host_port(address)
    return socket.create_connection((host, port), timeout=TIMEOUT)


def read_all(sock):
    chunks = []
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def mode_tcp(address):
    """Send a request, half-close, print everything that comes back."""
    with connect(address) as sock:
        sock.sendall(b"hello")
        sock.shutdown(socket.SHUT_WR)
        sys.stdout.write(read_all(sock).decode())


def mode_udp(address):
    host, port = split_host_port(address)
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(TIMEOUT)
        sock.sendto(b"ping?", (host, port))
        try:
            data, _ = sock.recvfrom(65536)
        except socket.timeout:
            sys.stdout.write("timeout")
            return
        sys.stdout.write(data.decode())


def mode_udp_twice(address, pause):
    """Two exchanges from one socket with a pause in between."""
    host, port = split_host_port(address)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(TIMEOUT)
        replies = []
        for _ in range(2):
            sock.sendto(b"ping?", (host, port))
            try:
                data, _ = sock.recvfrom(65536)
                replies.append(data.decode())
            except socket.timeout:
                replies.append("timeout")
            time.sleep(float(pause))
        sys.stdout.write(" ".join(replies))


def mode_udp_size(size, address):
    """One datagram of the given size; prints the size of the echo."""
    host, port = split_host_port(address)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(TIMEOUT)
        payload = os.urandom(int(size))
        sock.sendto(payload, (host, port))
        try:
            data, _ = sock.recvfrom(65535)
        except socket.timeout:
            sys.stdout.write("timeout")
            return
        sys.stdout.write(f"{len(data)} {'same' if data == payload else 'different'}")


def mode_udp_multi(*addresses):
    """One socket talking to several destinations, replies matched by sender."""
    targets = [split_host_port(a) for a in addresses]
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(TIMEOUT)
        for index, target in enumerate(targets):
            sock.sendto(f"msg{index}".encode(), target)
        replies = {}
        try:
            while len(replies) < len(targets):
                data, sender = sock.recvfrom(65536)
                replies[sender] = data.decode()
        except socket.timeout:
            pass
        sys.stdout.write(" ".join(replies.get(target, "timeout") for target in targets))


def mode_tcp_many(count, address):
    """Many concurrent connections at once; prints how many got their echo."""
    import threading

    host, port = split_host_port(address)
    good = [0]
    lock = threading.Lock()

    def one():
        try:
            with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
                sock.sendall(b"hello")
                sock.shutdown(socket.SHUT_WR)
                if read_all(sock) == b"echo:hello":
                    with lock:
                        good[0] += 1
        except OSError:
            pass

    threads = [threading.Thread(target=one) for _ in range(int(count))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    sys.stdout.write(f"{good[0]}/{count}")


def mode_udp_burst(count, address):
    """A burst of datagrams from one socket; prints how many replies came back."""
    host, port = split_host_port(address)
    count = int(count)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        # a program that fires bursts sizes its own receive buffer for them
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
        sock.settimeout(2.0)
        for index in range(count):
            sock.sendto(f"burst{index}".encode(), (host, port))
        seen = set()
        try:
            while len(seen) < count:
                data, _ = sock.recvfrom(65536)
                seen.add(data)
        except socket.timeout:
            pass
        sys.stdout.write(f"{len(seen)}/{count}")


def mode_dns(name, family="A"):
    """Resolve through libc, the way applications do."""
    af = socket.AF_INET6 if family == "AAAA" else socket.AF_INET
    try:
        infos = socket.getaddrinfo(name, None, af, socket.SOCK_STREAM)
    except socket.gaierror as error:
        sys.stdout.write(f"error:{error.errno}")
        return
    sys.stdout.write(",".join(sorted({info[4][0] for info in infos})))


def mode_dns_tcp(name):
    """Ask the local resolver over TCP directly."""
    query = dnswire.build_query(name, dnswire.TYPE_A)
    with socket.create_connection(("127.0.0.1", 53), timeout=TIMEOUT) as sock:
        sock.sendall(struct.pack("!H", len(query)) + query)
        length = struct.unpack("!H", recv_exact(sock, 2))[0]
        ips, _ = dnswire.parse_answer_ips(recv_exact(sock, length))
    sys.stdout.write(",".join(ips))


def mode_dns_raw(name, qtype):
    """Ask the local resolver over UDP and describe the answer on the wire."""
    qtype = int(qtype)
    query = dnswire.build_query(name, qtype, ident=0x4242)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(TIMEOUT)
        sock.sendto(query, ("127.0.0.1", 53))
        answer, _ = sock.recvfrom(65536)
    ident, flags, qdcount, ancount = dnswire.parse_header(answer)
    _, _, qname, aqtype = dnswire.parse_question(answer)
    ips, truncated = dnswire.parse_answer_ips(answer)
    sys.stdout.write(
        f"id={ident:#x} response={int(bool(flags & dnswire.FLAG_RESPONSE))} "
        f"rcode={dnswire.rcode(flags)} tc={int(truncated)} question={qname}/{aqtype} "
        f"questions={qdcount} answers={ancount} ips={','.join(ips)}"
    )


def recv_exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError("connection closed")
        data += chunk
    return data


def mode_refused(address):
    try:
        with connect(address):
            sys.stdout.write("connected")
    except ConnectionRefusedError:
        sys.stdout.write("refused")
    except socket.timeout:
        sys.stdout.write("timeout")
    except OSError as error:
        sys.stdout.write(f"error:{error.errno}")


def mode_idle(address, seconds):
    """Stay silent on an open connection, then see whether it survived."""
    with connect(address) as sock:
        time.sleep(float(seconds))
        try:
            sock.sendall(b"x")
            sock.shutdown(socket.SHUT_WR)
            data = read_all(sock)
        except OSError:
            data = b""
        sys.stdout.write("open" if data else "closed")


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def mode_ping(ip):
    """ICMP echo through an unprivileged ping socket."""
    if ":" in ip:
        family, proto, request, reply = socket.AF_INET6, socket.IPPROTO_ICMPV6, 128, 129
    else:
        family, proto, request, reply = socket.AF_INET, socket.IPPROTO_ICMP, 8, 0
    try:
        sock = socket.socket(family, socket.SOCK_DGRAM, proto)
    except OSError as error:
        sys.stdout.write(f"error:{error.errno}")
        return
    with sock:
        sock.settimeout(TIMEOUT)
        payload = b"wirez-ping"
        header = struct.pack("!BBHHH", request, 0, 0, 0, 1)
        if family == socket.AF_INET:
            header = struct.pack("!BBHHH", request, 0, checksum(header + payload), 0, 1)
        sock.sendto(header + payload, (ip, 0))
        try:
            data, _ = sock.recvfrom(65536)
        except socket.timeout:
            sys.stdout.write("timeout")
            return
        if data[0] == reply and data.endswith(payload):
            sys.stdout.write("reply")
        else:
            sys.stdout.write(f"unexpected:{data.hex()}")


def mode_file(path):
    sys.stdout.write(open(path).read())


def mode_fds():
    """Descriptor numbers the program holds, apart from the listing itself."""
    fds = sorted(int(name) for name in os.listdir("/proc/self/fd"))
    sys.stdout.write(" ".join(str(fd) for fd in fds[:-1]))


def mode_exit(code):
    sys.exit(int(code))


def mode_signal(number):
    os.kill(os.getpid(), int(number))


def mode_hostname():
    sys.stdout.write(socket.gethostname())


def mode_id():
    sys.stdout.write(f"{os.getuid()} {os.getgid()}")


def mode_sleep(seconds):
    print(os.getpid(), flush=True)
    time.sleep(float(seconds))


MODES = {
    "tcp": mode_tcp,
    "udp": mode_udp,
    "udp-multi": mode_udp_multi,
    "udp-size": mode_udp_size,
    "udp-twice": mode_udp_twice,
    "tcp-many": mode_tcp_many,
    "udp-burst": mode_udp_burst,
    "dns": mode_dns,
    "dns-tcp": mode_dns_tcp,
    "dns-raw": mode_dns_raw,
    "refused": mode_refused,
    "idle": mode_idle,
    "ping": mode_ping,
    "file": mode_file,
    "fds": mode_fds,
    "exit": mode_exit,
    "signal": mode_signal,
    "id": mode_id,
    "hostname": mode_hostname,
    "sleep": mode_sleep,
}


if __name__ == "__main__":
    MODES[sys.argv[1]](*sys.argv[2:])
    sys.stdout.flush()
