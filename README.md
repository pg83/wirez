# wirez

**wirez** redirects all TCP/UDP traffic from any given program to a SOCKS5 proxy, blocking other IP traffic (ICMP, SCTP, etc).

Unlike [tsocks](https://linux.die.net/man/8/tsocks), [proxychains](http://proxychains.sourceforge.net/) or
[proxychains-ng](https://github.com/rofl0r/proxychains-ng), wirez does not rely on the [LD_PRELOAD hack](https://stackoverflow.com/questions/426230/what-is-the-ld-preload-trick),
which only works for dynamically linked programs (e.g. [Go binaries can't be proxied by proxychains-ng](https://github.com/rofl0r/proxychains-ng/issues/199)).

Instead, wirez creates a rootless Linux container with a separate network namespace and runs a userspace network stack ([gVisor netstack](https://github.com/google/gvisor)) on a TUN device inside it. All traffic from the containerized process goes through the TUN, gets intercepted by the userspace stack, and is forwarded through the SOCKS5 proxy. This approach is transparent to the application — no library hooking, no recompilation, works with any binary.

## Installation

```
go build
```

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

The `-L` flag maps local ports to specific destinations directly, bypassing the SOCKS5 proxy. This is useful when the proxy doesn't support UDP ASSOCIATE (e.g. SSH, Tor).

Forward DNS directly to 1.1.1.1, everything else through proxy:

```
wirez -F 127.0.0.1:1234 -L 53:1.1.1.1:53/udp -- curl example.com
```

Redirect TCP traffic to `10.10.10.10:2345` directly to `127.0.0.1:4567`:

```
wirez -F 127.0.0.1:1234 -L 10.10.10.10:2345:127.0.0.1:4567/tcp bash
```

### Proxy chaining

Multiple `-F` flags create a proxy chain:

```
wirez -F proxy1:1080 -F proxy2:1080 -- curl example.com
```

### Flags

| Flag | Description |
|------|-------------|
| `-F address` | SOCKS5 proxy address (required, repeatable for chaining) |
| `-L mapping` | Local address mapping `[target_host:]port:host:hostport[/proto]` |
| `-v` | Increase log verbosity (repeat for more: `-vv`, `-vvv`) |
| `-q` | Suppress all log output |
| `-uid int` | Set UID of container process |
| `-gid int` | Set GID of container process |

## License

MIT. See [LICENSE](LICENSE).
