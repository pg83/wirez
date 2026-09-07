import os

import build

# wirez: transparent SOCKS5/HTTP proxifier for Linux, written in Go. The Go
# dependencies come from the module cache; go.sum pins them.

build.flags.allow({
    "race": {
        "descr": "run the Go tests under the race detector (needs cgo and a C compiler)",
        "default": "",
    },
})


def touch(path):
    return [
        "python3",
        "-c",
        f"from pathlib import Path; p=Path(r'{path}'); p.parent.mkdir(parents=True, exist_ok=True); p.touch()",
    ]


GO_SOURCES = [
    path for path in build.glob("$(S)/*.go")
    if not path.endswith("_test.go")
]
GO_TEST_SOURCES = build.glob("$(S)/*_test.go")
GO_MODULE = ["$(S)/go.mod", "$(S)/go.sum"]
GO_INPUTS = [*GO_SOURCES, *GO_MODULE]

GO_ENV = {
    "CGO_ENABLED": "0",
    "GOCACHE": "$(B)/gocache",
    "GOFLAGS": "-buildvcs=false",
    "GOTOOLCHAIN": "local",
    "GOWORK": "off",
}

wirez = command(
    name="wirez",
    inputs=GO_INPUTS,
    outputs=["$(B)/bin/wirez"],
    cmd=[
        "go", "build",
        "-trimpath",
        "-o", "$(B)/bin/wirez",
        ".",
    ],
    cwd="$(S)",
    env=GO_ENV,
    descr="GO",
    color="cyan",
)

gofmt_stamp = "$(B)/tests/gofmt.stamp"
gofmt_check = command(
    name="gofmt",
    inputs=[*GO_SOURCES, *GO_TEST_SOURCES, "$(S)/dev/gofmt_check.py"],
    outputs=[gofmt_stamp],
    cmd=[
        ["python3", "$(S)/dev/gofmt_check.py", *GO_SOURCES, *GO_TEST_SOURCES],
        touch(gofmt_stamp),
    ],
    cwd="$(S)",
    env=GO_ENV,
    descr="FM",
    color="green",
)

go_vet_stamp = "$(B)/tests/go_vet.stamp"
go_vet = command(
    name="go_vet",
    inputs=[*GO_INPUTS, *GO_TEST_SOURCES],
    outputs=[go_vet_stamp],
    cmd=[
        ["go", "vet", "."],
        touch(go_vet_stamp),
    ],
    cwd="$(S)",
    env=GO_ENV,
    descr="VT",
    color="green",
)

# The test binary doubles as wirez itself (see TestMain in integration_test.go)
# and needs /dev/net/tun plus unprivileged user namespaces for the container
# test; it skips that test where they are missing, unless
# WIREZ_TEST_CONTAINER_REQUIRED is set (CI does), which turns the skip into a
# failure. The variable is part of the node so that flipping it reruns the test.
go_test_env = {
    **GO_ENV,
    "WIREZ_TEST_CONTAINER_REQUIRED": os.environ.get("WIREZ_TEST_CONTAINER_REQUIRED", ""),
}
go_test_cmd = ["go", "test", "-count=1", "-timeout=10m"]

if build.flags.race:
    go_test_env["CGO_ENABLED"] = "1"
    go_test_cmd.append("-race")

go_test_stamp = "$(B)/tests/go_test.stamp"
go_test = command(
    name="go_test",
    inputs=[*GO_INPUTS, *GO_TEST_SOURCES],
    outputs=[go_test_stamp],
    cmd=[
        [*go_test_cmd, "."],
        touch(go_test_stamp),
    ],
    cwd="$(S)",
    env=go_test_env,
    descr="UT",
    color="green",
)

group("install", wirez)
group("test", gofmt_check, go_vet, go_test)
