// SPDX-License-Identifier: Apache-2.0

package livestack

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fatalTB records the first Fatal/Fatalf and aborts the call under test by panicking, so the
// t.Fatal branches of Env/Pool can be asserted on without failing this test.
type fatalTB struct {
	testing.TB
	msg      string
	cleanups []func()
}

type fatalAbort struct{}

func (f *fatalTB) Helper()           {}
func (f *fatalTB) Fatal(args ...any) { f.Fatalf("%v", args...) }
func (f *fatalTB) Fatalf(format string, a ...any) {
	f.msg = fmt.Sprintf(format, a...)
	panic(fatalAbort{})
}
func (f *fatalTB) Cleanup(fn func()) { f.cleanups = append(f.cleanups, fn) }
func (f *fatalTB) run(t *testing.T, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(fatalAbort); !ok {
				panic(r)
			}
		}
		for _, c := range f.cleanups {
			c()
		}
	}()
	fn()
}

func TestEnvFrom_ProcessEnvWins(t *testing.T) {
	t.Setenv("LIVESTACK_TEST_KEY", "from-env")
	envPath := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envPath, []byte("LIVESTACK_TEST_KEY=from-file\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := envFrom(t, envPath, "LIVESTACK_TEST_KEY"); got != "from-env" {
		t.Fatalf("got %q, want process env value", got)
	}
}

func TestEnvFrom_FallsBackToFile(t *testing.T) {
	t.Setenv("LIVESTACK_TEST_KEY", "")
	envPath := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envPath, []byte("# c\nLIVESTACK_TEST_KEY = from-file\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := envFrom(t, envPath, "LIVESTACK_TEST_KEY"); got != "from-file" {
		t.Fatalf("got %q, want file value", got)
	}
}

func TestEnvFrom_FileMissing_Fatal(t *testing.T) {
	t.Setenv("LIVESTACK_TEST_KEY", "")
	f := &fatalTB{}
	f.run(t, func() { envFrom(f, filepath.Join(t.TempDir(), "absent"), "LIVESTACK_TEST_KEY") })
	if !strings.HasPrefix(f.msg, "dbtest: open ") || !strings.Contains(f.msg, "make test-stack-up") {
		t.Fatalf("unexpected fatal: %q", f.msg)
	}
}

func TestEnvFrom_KeyAbsent_Fatal(t *testing.T) {
	t.Setenv("LIVESTACK_TEST_KEY", "")
	envPath := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envPath, []byte("OTHER=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f := &fatalTB{}
	f.run(t, func() { envFrom(f, envPath, "LIVESTACK_TEST_KEY") })
	if f.msg != "dbtest: LIVESTACK_TEST_KEY not set (in the environment or "+envPath+")" {
		t.Fatalf("unexpected fatal: %q", f.msg)
	}
}

func TestEnvAndTestStackEnv_ReadProcessEnv(t *testing.T) {
	t.Setenv("LIVESTACK_TEST_KEY", "v")
	if InPublicMode() {
		t.Skip("public mode: Env refuses by design; TargetsLiveStack is covered in guard_test.go")
	}
	if Env(t, "LIVESTACK_TEST_KEY") != "v" || TestStackEnv(t, "LIVESTACK_TEST_KEY") != "v" {
		t.Fatal("process env value not returned")
	}
}

func TestPool_BadParam_ConnectFatal(t *testing.T) {
	if InPublicMode() {
		t.Skip("public mode: Pool refuses by design")
	}
	t.Setenv("POSTGRES_HOST_PORT", "1")
	t.Setenv("POSTGRES_DB", "x")
	f := &fatalTB{}
	f.run(t, func() { Pool(f, "u", "p", "pool_max_conns=notanumber") })
	if !strings.HasPrefix(f.msg, "dbtest: connect as u: ") {
		t.Fatalf("unexpected fatal: %q", f.msg)
	}
}

func TestPool_WrongPassword_PingFatal(t *testing.T) {
	if os.Getenv("POSTGRES_HOST_PORT") == "" || InPublicMode() {
		t.Skip("needs the isolated test stack in the process env (make test-stack-up)")
	}
	f := &fatalTB{}
	f.run(t, func() { Pool(f, "kiban", "definitely-wrong-password") })
	if !strings.HasPrefix(f.msg, "dbtest: ping as kiban: ") {
		t.Fatalf("unexpected fatal: %q", f.msg)
	}
	if len(f.cleanups) != 1 {
		t.Fatalf("pool.Close not registered in Cleanup: %d", len(f.cleanups))
	}
}

func TestAdminPool_Connects(t *testing.T) {
	if os.Getenv("POSTGRES_HOST_PORT") == "" || InPublicMode() {
		t.Skip("needs the isolated test stack in the process env (make test-stack-up)")
	}
	if AdminPool(t) == nil {
		t.Fatal("nil pool")
	}
}
