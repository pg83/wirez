# Style Guide

## Coding conventions

- Git author: `claude <claude@users.noreply.github.com>`. Commit messages in English.

## Blank lines around control blocks

Before and after `if`, `for`, `switch`, `select`, `go func`, `defer func` — add a blank line.
Exception: no blank line if the block is the first or last statement inside `{}`.

## Blank lines before `return`

Always add a blank line before `return`.
Exception: no blank line if `return` is the first statement after `{`.

## Logical grouping

Consecutive one-liners (`Throw*`, `defer`, `:=`, `=`) that form a single logical operation stay together without blank lines. Between separate logical operations — add a blank line.

Example — opening a file and deferring close is one operation:

```go
f := Throw2(os.Open(path))
defer f.Close()

socksAddrs := parseProxyFile(f)  // next operation
```

Example — setting up a resource is one operation, using it is another:

```go
dev := Throw2(netlink.LinkByName(device))
Throw(netlink.LinkSetUp(dev))

addr := Throw2(netlink.ParseAddr(networkAddr))
Throw(netlink.AddrAdd(dev, addr))

return dev, addr
```

## Build and test

Use the monorepo `build` runner, never `go build`/`go test` directly:

```
./build              # .build/bin/wirez, published as ./wirez
./build test         # gofmt, go vet, go test
./build -Drace test  # same under the race detector
```

Go dependencies are not vendored; `go.mod`/`go.sum` pin them and the module cache supplies them. CI (`.github/workflows/ci.yml`) calls `./build` too.
