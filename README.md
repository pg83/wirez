# wirez

**wirez** redirects all TCP/UDP traffic from any given program to a SOCKS5 (or HTTP CONNECT) proxy, blocking other IP traffic (SCTP, ICMP other than ping, etc).

Unlike [tsocks](https://linux.die.net/man/8/tsocks), [proxychains](http://proxychains.sourceforge.net/) or
[proxychains-ng](https://github.com/rofl0r/proxychains-ng), wirez does not rely on the [LD_PRELOAD hack](https://stackoverflow.com/questions/426230/what-is-the-ld-preload-trick),
which only works for dynamically linked programs (e.g. [Go binaries can't be proxied by proxychains-ng](https://github.com/rofl0r/proxychains-ng/issues/199)).

Instead, wirez creates a rootless Linux container with a separate network namespace and runs a userspace network stack ([gVisor netstack](https://github.com/google/gvisor)) on a TUN device inside it. All traffic from the containerized process goes through the TUN, gets intercepted by the userspace stack, and is forwarded through the proxy. This approach is transparent to the application — no library hooking, no recompilation, works with any binary.

## Building

wirez is built with the monorepo's `build` runner (a copy lives next to `build.py`). It needs Go and Python 3.10+:

```
./build          # builds .build/bin/wirez and publishes the ./wirez symlink
./build test     # gofmt, go vet, the Go unit tests and the integration tests
./build -Drace test
```

The integration tests live in `tst/test_*.py`, one build node each (`./build it_dns`, ...). Every one of them runs the real binary around fake proxies, DNS and echo servers on loopback, with `tst/client.py` generating traffic inside the container. They need `/dev/net/tun` and unprivileged user namespaces and are skipped where those are missing; set `WIREZ_TEST_CONTAINER_REQUIRED=1` (CI does) to make that a failure instead.

## Usage

Forward all traffic through a SOCKS5 proxy:

```
wirez -F 127.0.0.1:1234 bash
```

Proxy a single command:

```
wirez -F 127.0.0.1:1234 -- curl example.com
```

### Local port forwarding

The `-L` flag maps local ports to specific destinations directly, bypassing the proxy. This is useful when the proxy doesn't support UDP ASSOCIATE (e.g. SSH, Tor).

Forward DNS directly to 1.1.1.1, everything else through proxy:

```
wirez -F 127.0.0.1:1234 -L 53:1.1.1.1:53/udp -- curl example.com
```

Redirect TCP traffic to `10.10.10.10:2345` directly to `127.0.0.1:4567`:

```
wirez -F 127.0.0.1:1234 -L 10.10.10.10:2345:127.0.0.1:4567/tcp bash
```

Inside the container `localhost` resolves to `127.0.0.1`/`::1` first, so servers binding `localhost` get an address that exists there, and to the TUN peer address (`10.1.1.2`) last. Connections to the TUN subnet are refused unless an `-L` mapping redirects them, so a service that is missing inside the container never turns into a request to the proxy.

### Bypass CIDR

The `-B` flag takes a CIDR; any destination whose literal IP falls in that network goes direct (no proxy, no rewrite). Repeatable. Useful for "everything in my LAN goes around the proxy":

```
wirez -F 127.0.0.1:1234 -B 10.0.0.0/8 -B 192.168.0.0/16 -- curl http://10.0.0.65:8012
```

`-L` rewrites are applied before the bypass check, so an explicit mapping wins even when the original destination falls into a bypass network. Matching is on the destination IP only — names go through the regular `-L`/proxy path. The TUN subnet (`10.1.1.0/24`) is always refused, even when a bypass network covers it.

### IPv6 and NAT64 (IPv6-only hosts)

By default the TUN carries IPv4 only and the `-D` resolver hides AAAA records. `-6` adds an IPv6 address (`2001:db8:1:1::1/64` — deliberately not a ULA, so that getaddrinfo keeps preferring IPv6 destinations) and a default route inside the container. TCP connections are accepted only after the upstream dial succeeds, so a failed dial shows up as "connection refused" and clients fall back to their next address. AAAA answers are then passed through **only** when at least one address in the answer is dialable directly (falls into a `-B` network); everything else still gets an empty AAAA so applications use IPv4 through the proxy:

```
wirez -F 127.0.0.1:1234 -D 2001:db8::53 -6 -B 2001:db8::/32 -- curl http://internal.example
```

On a host without IPv4 connectivity that relies on NAT64, pass the NAT64 prefix with `-nat64`. Bypassed IPv4 destinations are then dialed through the prefix (`64:ff9b::/96` + IPv4), and DNS64-synthesized IPv6 destinations are unmapped back to IPv4 before the `-L`/`-B`/proxy decision, so the IPv4 rules govern them:

```
wirez -F 127.0.0.1:1234 -D 2001:db8::53 -6 -nat64 64:ff9b::/96 -B 2001:db8::/32 -B 10.0.0.0/8 -- bash
```

### Proxy chaining

Multiple `-F` flags create a proxy chain:

```
wirez -F proxy1:1080 -F proxy2:1080 -- curl example.com
```

### HTTP CONNECT proxies

`-F http://[user:pass@]host:port` tunnels TCP through an HTTP proxy with `CONNECT`. HTTP has no UDP, so as soon as an HTTP hop is in the chain, UDP is refused (use `-L` to route DNS around it, or `-D`):

```
wirez -F http://proxy.corp.example:3128 -D 10.0.0.53 -- curl example.com
```

SOCKS5 proxies accept `socks5://user:pass@host:port` for authentication; `socks5h://` is accepted as an alias.

### Local DNS resolver

The `-D` flag starts a tiny DNS resolver on `127.0.0.1:53` (UDP and TCP) inside the container and points `/etc/resolv.conf` at it. The resolver runs in the host network namespace, so it forwards queries to the given upstream DNS **directly, bypassing the proxy**. It answers `AAAA` queries with an empty `NOERROR` (NODATA), so applications only ever see IPv4 addresses and fall back to IPv4 — handy when the proxy chain has no working IPv6.

```
wirez -F 127.0.0.1:1234 -D 1.1.1.1 -D 8.8.8.8 -- curl example.com
```

The upstream accepts a bare IPv4/IPv6 address (port 53 implied) or an explicit `host:port`. `-D` is repeatable: upstreams are tried in order, and the one that answered last is asked first from then on. Answers that come back truncated over UDP (TC bit) are re-fetched over TCP.

The container's `/etc/resolv.conf` keeps the host's `search` and `options` lines, and `/etc/hosts` keeps the host's entries, so short names and custom host entries keep working inside.

### Timeouts

| Flag | Default | Meaning |
|------|---------|---------|
| `-connect-timeout` | `10s` | a dial including the proxy handshakes |
| `-tcp-timeout` | `0` | idle timeout of TCP connections; `0` disables it and leaves liveness to TCP keepalive |
| `-udp-timeout` | `15s` | idle timeout of UDP flows |

### ping

wirez answers ICMP echo requests for any address itself, so `ping` inside the container reports the TUN round trip rather than the real host. No other ICMP passes.

### IPv6

`-F`, `-L` and `-B` all accept IPv6. Literal IPv6 addresses must be bracketed (`[..]`) so the address and port stay unambiguous; `-B` takes a plain IPv6 CIDR:

```
wirez -F '[::1]:1080' -B 'fd00::/8' -L '53:[2606:4700:4700::1111]:53/udp' -- curl -6 example.com
```

### Flags

| Flag | Description |
|------|-------------|
| `-F address` | Proxy to forward through: `[socks5://]host:port` or `http://host:port` (required, repeatable for chaining) |
| `-L mapping` | Local address mapping `[target_host:]port:host:hostport[/proto]` |
| `-B cidr` | Bypass CIDR — destinations in this network go direct, not via the proxy (repeatable) |
| `-D address` | Upstream DNS for the local resolver on `127.0.0.1:53` (forwarded direct, bypassing the proxy; repeatable for failover); IPv4-only unless `-6` |
| `-6` | Enable IPv6 on the TUN; AAAA answers are kept only for addresses reachable via `-B` |
| `-nat64 prefix` | NAT64 `/96` prefix of the host: bypassed IPv4 is dialed through it, synthesized IPv6 is unmapped |
| `-connect-timeout d` | Timeout of a dial, proxy handshakes included |
| `-tcp-timeout d` | Idle timeout of TCP connections, `0` disables it |
| `-udp-timeout d` | Idle timeout of UDP flows |
| `-v` | Increase log verbosity (repeat for more: `-v -v`) |
| `-q` | Suppress all log output |
| `-uid int` | Set UID of container process |
| `-gid int` | Set GID of container process |

## License

MIT. See [LICENSE](LICENSE).
