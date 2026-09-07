"""Just enough of the DNS wire format (RFC 1035) for the tests: build a query,
parse a question, build an answer with A/AAAA records, read the answers back."""

import socket
import struct

TYPE_A = 1
TYPE_AAAA = 28
CLASS_IN = 1
FLAG_RESPONSE = 0x8000
FLAG_TRUNCATED = 0x0200
FLAG_RD = 0x0100
FLAG_RA = 0x0080


def encode_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        if label:
            out += bytes([len(label)]) + label.encode()
    return out + b"\0"


def decode_name(msg, offset):
    labels = []
    jumped = False
    end = offset
    while True:
        length = msg[offset]
        if length & 0xC0 == 0xC0:
            pointer = struct.unpack("!H", msg[offset:offset + 2])[0] & 0x3FFF
            if not jumped:
                end = offset + 2
            offset = pointer
            jumped = True
            continue
        offset += 1
        if length == 0:
            if not jumped:
                end = offset
            break
        labels.append(msg[offset:offset + length].decode())
        offset += length
    return ".".join(labels) + ".", end


def build_query(name, qtype, ident=0x1234):
    header = struct.pack("!HHHHHH", ident, FLAG_RD, 1, 0, 0, 0)
    return header + encode_name(name) + struct.pack("!HH", qtype, CLASS_IN)


def parse_question(msg):
    """Returns (ident, flags, name, qtype)."""
    ident, flags, qdcount = struct.unpack("!HHH", msg[:6])
    if qdcount < 1:
        raise ValueError("no question")
    name, end = decode_name(msg, 12)
    qtype = struct.unpack("!HH", msg[end:end + 4])[0]
    return ident, flags, name, qtype


def build_answer(query, ips, truncated=False):
    """Answers the query with the given addresses (A or AAAA by address family)."""
    ident, _, name, qtype = parse_question(query)
    flags = FLAG_RESPONSE | FLAG_RD | FLAG_RA
    if truncated:
        flags |= FLAG_TRUNCATED
    question = encode_name(name) + struct.pack("!HH", qtype, CLASS_IN)
    answers = b""
    for ip in ips:
        if ":" in ip:
            rtype, rdata = TYPE_AAAA, socket.inet_pton(socket.AF_INET6, ip)
        else:
            rtype, rdata = TYPE_A, socket.inet_pton(socket.AF_INET, ip)
        answers += b"\xc0\x0c" + struct.pack("!HHIH", rtype, CLASS_IN, 60, len(rdata)) + rdata
    header = struct.pack("!HHHHHH", ident, flags, 1, len(ips), 0, 0)
    return header + question + answers


def parse_answer_ips(msg):
    """Returns the addresses of the A/AAAA records in the answer section."""
    _, flags, qdcount, ancount = struct.unpack("!HHHH", msg[:8])
    offset = 12
    for _ in range(qdcount):
        _, offset = decode_name(msg, offset)
        offset += 4
    ips = []
    for _ in range(ancount):
        _, offset = decode_name(msg, offset)
        rtype, _, _, rdlength = struct.unpack("!HHIH", msg[offset:offset + 10])
        offset += 10
        rdata = msg[offset:offset + rdlength]
        offset += rdlength
        if rtype == TYPE_A:
            ips.append(socket.inet_ntop(socket.AF_INET, rdata))
        elif rtype == TYPE_AAAA:
            ips.append(socket.inet_ntop(socket.AF_INET6, rdata))
    return ips, bool(flags & FLAG_TRUNCATED)
