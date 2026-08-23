package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestInitialUserNamespaceRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires euid 0 to exercise the runtime predicate")
	}

	data, err := os.ReadFile("/proc/self/uid_map")

	if err != nil {
		t.Fatal(err)
	}

	fields := strings.Fields(string(data))
	want := len(fields) >= 3 && fields[0] == "0" && fields[1] == "0" && fields[2] != "1"

	if got := isInitialUserNamespaceRoot(); got != want {
		t.Fatalf("isInitialUserNamespaceRoot() = %v, want %v; uid_map=%q", got, want, data)
	}
}

func TestNestedUserNamespaceUsesRootlessPath(t *testing.T) {
	if os.Getenv("WIREZ_TEST_NESTED") == "1" {
		if isInitialUserNamespaceRoot() {
			t.Fatal("nested user namespace was classified as initial root")
		}

		return
	}

	cmd := exec.Command("unshare", "-r", "-U", os.Args[0], "-test.run=TestNestedUserNamespaceUsesRootlessPath")
	cmd.Env = append(os.Environ(), "WIREZ_TEST_NESTED=1")

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("nested user namespaces unavailable: %v: %s", err, out)
	}
}
