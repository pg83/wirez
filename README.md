# wirez

[![CI](https://github.com/pg83/wirez/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/pg83/wirez/actions/workflows/ci.yml)
[![Go version](https://img.shields.io/github/go-mod/go-version/pg83/wirez)](go.mod)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**wirez** runs a program in a rootless container whose only way out is a SOCKS5 or HTTP CONNECT proxy. Every TCP connection and UDP packet the program makes goes through the proxy; nothing else gets out.

Unlike [tsocks](https://linux.die.net/man/8/tsocks), [proxychains](http://proxychains.sourceforge.net/) or [proxychains-ng](https://github.com/rofl0r/proxychains-ng), it does not rely on the [LD_PRELOAD hack](https://stackoverflow.com/questions/426230/what-is-the-ld-preload-trick), which only works for dynamically linked programs ([Go binaries can't be proxied by proxychains-ng](https://github.com/rofl0r/proxychains-ng/issues/199)). wirez gives the program its own network namespace with a TUN device and runs a userspace network stack ([gVisor netstack](https://github.com/google/gvisor)) on it: whatever the program sends is terminated there and forwarded through the proxy. No library hooking, no recompilation, any binary, no root.

## Usage

```
wirez -F 127.0.0.1:1080 bash                                        # a shell where everything is proxied
wirez -F 127.0.0.1:1080 -- curl example.com                         # a single command
wirez -F socks5://user:pass@a:1080 -F http://b:3128 -- git fetch    # a chain: each hop is reached through the previous one
```

`-F` takes `[socks5://][user:pass@]host:port` or `http://[user:pass@]host:port`. HTTP CONNECT carries TCP only: with an HTTP hop in the chain, UDP is refused (route DNS around it with `-L` or `-D`).

### Where a connection goes

For every destination the program dials, in this order:

1. **An `-L` mapping matches** (`host:port`, or a bare port for any host): connect directly to the mapped target instead. This is how UDP gets past a proxy without UDP ASSOCIATE (SSH, Tor):

   ```
   wirez -F 127.0.0.1:1080 -L 53:1.1.1.1:53/udp -- curl example.com          # DNS straight to 1.1.1.1
   wirez -F 127.0.0.1:1080 -L 10.10.10.10:2345:127.0.0.1:4567/tcp bash       # one TCP destination to a local port
   ```

2. **The TUN subnet** (`10.1.1.0/24`) is refused. Inside, `localhost` resolves to loopback first and to `10.1.1.2` last, so a service that is missing in the container gets a refusal, never a request to the proxy; `-L 10.1.1.2:port:...` redirects it.

3. **A `-B` network contains the destination IP**: go direct, no proxy. Only literal IPs match, names never do:

   ```
   wirez -F 127.0.0.1:1080 -B 10.0.0.0/8 -B 192.168.0.0/16 -- curl http://10.0.0.65:8012
   ```

4. **Otherwise the proxy chain.**

A destination the chain cannot reach is reported as "connection refused" at once, so programs with several addresses to try move on. ICMP echo is answered locally, so `ping` works; no other ICMP passes.

### DNS

Without `-D`, DNS is ordinary UDP/TCP traffic and follows the rules above: through the proxy, or around it with `-L 53:...`. `-D` starts a resolver on `127.0.0.1:53` inside the container, points `/etc/resolv.conf` at it and forwards queries to the upstream **directly, never through the proxy**:

```
wirez -F 127.0.0.1:1080 -D 1.1.1.1 -D 8.8.8.8 -- curl example.com
```

Upstreams are `ip` or `host:port`; several are tried in order, starting with the one that answered last time. Truncated UDP answers are re-fetched over TCP. `AAAA` queries get an empty answer, so programs stick to IPv4 (see below). The host's `search`/`options` lines and `/etc/hosts` entries stay in effect inside.

### IPv6, IPv6-only hosts

The container has IPv4 only unless `-6` is given, because proxy chains rarely carry IPv6. With `-6` the resolver lets an `AAAA` answer through only when one of its addresses falls into a `-B` network, so IPv6 is used exactly where it is reachable directly. On a host that itself reaches IPv4 through NAT64, `-nat64 64:ff9b::/96` dials bypassed IPv4 destinations through the prefix and unmaps DNS64-synthesized addresses back to IPv4 before the routing decision:

```
wirez -F '[2001:db8::1]:1080' -D 2001:db8::53 -6 -nat64 64:ff9b::/96 -B 2001:db8::/32 -B 10.0.0.0/8 -- bash
```

IPv6 literals are bracketed everywhere they carry a port: `-F '[::1]:1080'`, `-L '53:[2606:4700:4700::1111]:53/udp'`.

### Flags

| Flag | Description |
|------|-------------|
| `-F address` | proxy: `[socks5://]host:port` (`socks5h://` too) or `http://host:port`, optional `user:pass@`; required, repeat to chain |
| `-L mapping` | direct mapping `[target_host:]port:host:hostport[/proto]`, proto `tcp` (default) or `udp`; repeatable |
| `-B cidr` | destinations in this network go direct; repeatable |
| `-D address` | upstream DNS for the local resolver; repeat for failover |
| `-6` | IPv6 inside the container |
| `-nat64 prefix` | the host's NAT64 `/96` prefix |
| `-connect-timeout d` | a dial, proxy handshakes included; default `10s` |
| `-tcp-timeout d` | idle timeout of TCP connections; default `0`, which leaves liveness to TCP keepalive |
| `-udp-timeout d` | idle timeout of UDP flows; default `15s` |
| `-uid n`, `-gid n` | run the program as this uid/gid; default: yours |
| `-v`, `-q` | more logging (repeatable), or none at all |

The program's exit status becomes wirez's (128 plus the signal number when a signal killed it), and the program dies with wirez.

## Development

```
nix develop          # Go, the build runner's Python and every program the tests drive
./build              # .build/bin/wirez, published as ./wirez
./build test         # gofmt, go vet, unit and end-to-end tests
./build -Drace test
```

`flake.nix` provides the dev shell; without it, `build` needs Go and Python 3.10+ on `PATH`, and the tests skip the programs they cannot find. The tests are `tst/test_*.py`, one build node each (`./build it_ssh`): every one runs the real binary, most of them with real programs (curl over HTTP/1.1, 2 and 3, sshd, git, iperf3, dig, real SOCKS5 and HTTP proxies, a static busybox) against real servers in a private network namespace where the servers sit on `192.0.2.1`, with some on a lossy link. They need `/dev/net/tun` and unprivileged user namespaces and skip otherwise; `WIREZ_TEST_CONTAINER_REQUIRED=1` (CI sets it) makes that a failure.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md): AI-assisted work with a human in the loop is preferred, unreviewed AI output is not accepted.

## License

MIT, see [LICENSE](LICENSE).
