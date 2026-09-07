import os

import build

# wirez: transparent SOCKS5/HTTP proxifier for Linux, written in Go. The Go
# dependencies come from the module cache; go.sum pins them.

build.flags.allow({
    "race": {
        "descr": "run the Go tests under the race detector (needs cgo and a C compiler)",
        "default": "",
    },
    "coverage": {
        "descr": "instrument the binary and the tests; `./build -Dcoverage coverage` writes $(B)/coverage.out",
        "default": "",
    },
})

COVERAGE = bool(build.flags.coverage)


def coverage_dir(name):
    return f"$(B)/coverage/{name}"


def mkdir(path):
    return [
        "python3",
        "-c",
        f"from pathlib import Path; Path(r'{path}').mkdir(parents=True, exist_ok=True)",
    ]


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

# With -Dcoverage the binary counts what it executes (Go's own instrumentation)
# and every process writes its counters to GOCOVERDIR at exit, so the
# end-to-end tests measure coverage of the real program.
wirez = command(
    name="wirez",
    inputs=GO_INPUTS,
    outputs=["$(B)/bin/wirez"],
    cmd=[
        "go", "build",
        "-trimpath",
        *(["-cover", "-covermode=atomic"] if COVERAGE else []),
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

go_test_env = dict(GO_ENV)
go_test_cmd = ["go", "test", "-count=1", "-timeout=10m"]
go_test_args = []
go_test_prelude = []

if build.flags.race:
    go_test_env["CGO_ENABLED"] = "1"
    go_test_cmd.append("-race")

if COVERAGE:
    go_test_cmd += ["-cover", "-covermode=atomic"]
    go_test_args = ["-args", f"-test.gocoverdir={coverage_dir('go_test')}"]
    go_test_prelude = [mkdir(coverage_dir("go_test"))]

go_test_stamp = "$(B)/tests/go_test.stamp"
go_test = command(
    name="go_test",
    inputs=[*GO_INPUTS, *GO_TEST_SOURCES],
    outputs=[go_test_stamp, *([coverage_dir("go_test")] if COVERAGE else [])],
    cmd=[
        *go_test_prelude,
        [*go_test_cmd, ".", *go_test_args],
        touch(go_test_stamp),
    ],
    cwd="$(S)",
    env=go_test_env,
    descr="UT",
    color="green",
)

# Integration tests: one node per tst/test_*.py, each driving the real binary
# around fake proxies and servers on loopback (see tst/lib.py). They need
# /dev/net/tun and unprivileged user namespaces and skip where those are
# missing, unless WIREZ_TEST_CONTAINER_REQUIRED is set (CI does), which turns
# the skip into a failure. The variable is part of the node so that flipping
# it reruns the tests.
INTEGRATION_LIB = ["$(S)/tst/lib.py", "$(S)/tst/dnswire.py", "$(S)/tst/client.py", "$(S)/tst/httpd.py", "$(S)/tst/h2stream.py"]

integration_tests = []
coverage_dirs = [coverage_dir("go_test")]
for test_path in build.glob("$(S)/tst/test_*.py"):
    test_name = test_path.rsplit("/", 1)[-1][len("test_"):-len(".py")]
    test_stamp = f"$(B)/tests/it_{test_name}.stamp"
    env = {
        "WIREZ_TEST_BINARY": wirez.outputs[0],
        "WIREZ_TEST_CONTAINER_REQUIRED": os.environ.get("WIREZ_TEST_CONTAINER_REQUIRED", ""),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    prelude = []
    outputs = [test_stamp]
    if COVERAGE:
        # the counters are a declared output so the coverage node sees them
        env["GOCOVERDIR"] = coverage_dir(f"it_{test_name}")
        prelude = [mkdir(env["GOCOVERDIR"])]
        coverage_dirs.append(env["GOCOVERDIR"])
        outputs.append(env["GOCOVERDIR"])
    integration_tests.append(command(
        name=f"it_{test_name}",
        inputs=[test_path, *INTEGRATION_LIB],
        outputs=outputs,
        deps=[wirez],
        cmd=[
            *prelude,
            ["python3", test_path],
            touch(test_stamp),
        ],
        cwd="$(S)",
        env=env,
        descr="IT",
        color="green",
    ))

group("install", wirez)
group("test", gofmt_check, go_vet, go_test, *integration_tests)

if COVERAGE:
    coverage = command(
        name="coverage",
        inputs=["$(S)/dev/coverage.py"],
        outputs=["$(B)/coverage.out"],
        deps=[go_test, *integration_tests],
        cmd=["python3", "$(S)/dev/coverage.py", "--output", "$(B)/coverage.out", *coverage_dirs],
        cwd="$(S)",
        env=GO_ENV,
        descr="CV",
        color="magenta",
    )
