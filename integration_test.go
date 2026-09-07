package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestMain lets the test binary stand in for wirez: runRun re-executes
// /proc/self/exe as "runc" for the container half, and the integration test
// runs the binary itself both as the wirez command and as the program inside
// the container.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "runc":
			exitOn(Try(func() { runContainer(os.Args[2:]) }))
		case "wirez":
			log := slog.New(slog.NewTextHandler(os.Stderr, nil))
			exitOn(Try(func() { runRun(log, os.Args[2:]) }))
		case "wirez-test-client":
			os.Exit(testClientMain(os.Args[2:]))
		}
	}

	os.Exit(m.Run())
}

func exitOn(e *Exception) {
	if e == nil {
		os.Exit(0)
	}

	var exitErr *exec.ExitError

	if errors.As(e, &exitErr) {
		os.Exit(exitCode(exitErr))
	}

	fmt.Fprintln(os.Stderr, e)
	os.Exit(1)
}

// testClientMain is the program run inside the container: it uses the
// network the way any application would and prints what it saw.
func testClientMain(args []string) int {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: wirez-test-client mode arg")

		return 2
	}

	mode, arg := args[0], args[1]

	fail := func(err error) int {
		fmt.Fprintln(os.Stderr, mode+":", err)

		return 1
	}

	switch mode {
	case "tcp":
		conn, err := net.DialTimeout("tcp", arg, testTimeout)

		if err != nil {
			return fail(err)
		}

		defer conn.Close()
		conn.SetDeadline(time.Now().Add(testTimeout))
		conn.Write([]byte("hello"))
		closeWrite(conn)

		data, err := io.ReadAll(conn)

		if err != nil {
			return fail(err)
		}

		fmt.Print(string(data))
	case "udp":
		conn, err := net.DialTimeout("udp", arg, testTimeout)

		if err != nil {
			return fail(err)
		}

		defer conn.Close()
		conn.SetDeadline(time.Now().Add(testTimeout))
		conn.Write([]byte("ping?"))

		buf := make([]byte, 64)
		n, err := conn.Read(buf)

		if err != nil {
			return fail(err)
		}

		fmt.Print(string(buf[:n]))
	case "dns":
		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		ips, err := (&net.Resolver{PreferGo: true}).LookupHost(ctx, arg)

		if err != nil {
			return fail(err)
		}

		fmt.Print(strings.Join(ips, ","))
	case "refused":
		conn, err := net.DialTimeout("tcp", arg, testTimeout)

		if err != nil {
			fmt.Print("refused")
		} else {
			conn.Close()
			fmt.Print("connected")
		}
	case "hosts":
		data, err := os.ReadFile("/etc/hosts")

		if err != nil {
			return fail(err)
		}

		fmt.Print(string(data))
	case "fds":
		entries, err := os.ReadDir("/proc/self/fd")

		if err != nil {
			return fail(err)
		}

		names := make([]string, 0, len(entries))

		for _, e := range entries {
			target, _ := os.Readlink("/proc/self/fd/" + e.Name())
			names = append(names, e.Name()+"="+target)
		}

		fmt.Print(strings.Join(names, " "))
	case "exit":
		code, err := strconv.Atoi(arg)

		if err != nil {
			return fail(err)
		}

		return code
	default:
		return fail(errors.New("unknown mode"))
	}

	return 0
}

// requireContainerSupport skips the test where the container cannot be
// created, unless WIREZ_TEST_CONTAINER_REQUIRED is set: CI sets it so that
// a silently skipped test cannot pass for a green run.
func requireContainerSupport(t *testing.T) {
	t.Helper()

	unsupported := func(format string, args ...any) {
		t.Helper()

		if os.Getenv("WIREZ_TEST_CONTAINER_REQUIRED") != "" {
			t.Fatalf(format, args...)
		}

		t.Skipf(format, args...)
	}

	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)

	if err != nil {
		unsupported("no TUN device: %v", err)
	}

	f.Close()

	if os.Geteuid() != 0 {
		if out, err := exec.Command("unshare", "-r", "-n", "true").CombinedOutput(); err != nil {
			unsupported("no unprivileged user namespaces: %v: %s", err, out)
		}
	}
}

// runWirez runs the test binary as wirez with the given arguments and returns
// what the containerized program printed.
func runWirez(t *testing.T, args ...string) (string, error) {
	t.Helper()

	exe, err := os.Executable()

	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, exe, append([]string{"wirez"}, args...)...)

	var stdout, stderr bytes.Buffer

	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()

	if err != nil {
		err = fmt.Errorf("%w\nstderr: %s", err, stderr.String())
	}

	return stdout.String(), err
}

func wirezTempDirs(t *testing.T) []string {
	t.Helper()

	dirs, err := filepath.Glob(filepath.Join(os.TempDir(), "wirez-*"))

	if err != nil {
		t.Fatal(err)
	}

	return dirs
}

func TestIntegrationContainer(t *testing.T) {
	requireContainerSupport(t)

	exe, err := os.Executable()

	if err != nil {
		t.Fatal(err)
	}

	backend := eofEchoServer(t)
	proxy := newSocks5TestServer(t, socks5TestConfig{backend: backend, udpBackend: udpEchoServer(t)})
	dns := fakeUpstream(t, answerWith(t, false, "192.0.2.1"), nil)
	tempDirsBefore := wirezTempDirs(t)

	run := func(t *testing.T, mode, arg string, extra ...string) string {
		t.Helper()

		args := append([]string{"-F", proxy.Addr(), "-D", dns, "-q"}, extra...)
		args = append(args, "--", exe, "wirez-test-client", mode, arg)
		out, err := runWirez(t, args...)

		if err != nil {
			t.Fatalf("wirez %s %s: %v", mode, arg, err)
		}

		return out
	}

	t.Run("tcp through the proxy", func(t *testing.T) {
		if got := run(t, "tcp", "192.0.2.1:8080"); got != "echo:hello" {
			t.Errorf("got %q, want \"echo:hello\"", got)
		}

		if !slices.Contains(proxy.Connects(), "192.0.2.1:8080") {
			t.Errorf("proxy saw CONNECT %v, want 192.0.2.1:8080 among them", proxy.Connects())
		}
	})

	t.Run("udp through the proxy", func(t *testing.T) {
		if got := run(t, "udp", "192.0.2.1:5353"); got != "ping?" {
			t.Errorf("got %q, want \"ping?\"", got)
		}
	})

	t.Run("dns through the local resolver", func(t *testing.T) {
		if got := run(t, "dns", "wirez.test"); got != "192.0.2.1" {
			t.Errorf("got %q, want \"192.0.2.1\"", got)
		}
	})

	t.Run("tun peer is refused without -L", func(t *testing.T) {
		if got := run(t, "refused", "10.1.1.2:9"); got != "refused" {
			t.Errorf("got %q, want \"refused\"", got)
		}

		if slices.Contains(proxy.Connects(), "10.1.1.2:9") {
			t.Error("the connection to the TUN peer reached the proxy")
		}
	})

	t.Run("-L redirects the tun peer directly", func(t *testing.T) {
		before := len(proxy.Connects())

		if got := run(t, "tcp", "10.1.1.2:9", "-L", "10.1.1.2:9:"+backend+"/tcp"); got != "echo:hello" {
			t.Errorf("got %q, want \"echo:hello\"", got)
		}

		if after := len(proxy.Connects()); after != before {
			t.Error("the -L mapped connection went through the proxy")
		}
	})

	t.Run("hosts keeps the host entries", func(t *testing.T) {
		got := run(t, "hosts", "")

		if !strings.Contains(got, "10.1.1.2 localhost\n") {
			t.Errorf("hosts lacks the TUN peer entry:\n%s", got)
		}

		for _, line := range strings.Split(readHostFile("/etc/hosts"), "\n") {
			if fields := strings.Fields(line); len(fields) > 0 && !strings.HasPrefix(fields[0], "#") {
				if !strings.Contains(got, line) {
					t.Errorf("host entry %q missing:\n%s", line, got)
				}

				break
			}
		}
	})

	t.Run("no descriptors leak into the program", func(t *testing.T) {
		// The program inherits whatever the test environment holds open
		// (and the Go runtime opens a few files of its own), so compare
		// against the same program run outside the container.
		baseline, err := exec.Command(exe, "wirez-test-client", "fds", "").Output()

		if err != nil {
			t.Fatal(err)
		}

		outside := strings.Fields(string(baseline))
		inside := strings.Fields(run(t, "fds", ""))

		if len(inside) != len(outside) {
			t.Errorf("program sees descriptors %v inside, %v outside", inside, outside)
		}
	})

	t.Run("exit code is propagated", func(t *testing.T) {
		_, err := runWirez(t, "-F", proxy.Addr(), "-q", "--", exe, "wirez-test-client", "exit", "3")

		var exitErr *exec.ExitError

		if !errors.As(err, &exitErr) || exitErr.ExitCode() != 3 {
			t.Errorf("wirez exited with %v, want status 3", err)
		}
	})

	t.Run("temp dirs are cleaned up", func(t *testing.T) {
		if after := wirezTempDirs(t); len(after) != len(tempDirsBefore) {
			t.Errorf("wirez-* temp dirs before %d, after %d: %v", len(tempDirsBefore), len(after), after)
		}
	})
}
