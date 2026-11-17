//go:build linux

package ebpf

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// Live anti-tamper test. Needs root, BPF-LSM and bpftool; opt in with
//
//	AURORA_LIVE_TAMPER_TEST=1 go test ./lib/provider/ebpf -run TestLiveTamper -v
//
// The test process is the protected "Aurora"; child shells play the attacker.
// Enforcement only lasts until the sensor is closed at the end of the test.
func TestLiveTamper(t *testing.T) {
	if os.Getenv("AURORA_LIVE_TAMPER_TEST") != "1" {
		t.Skip("set AURORA_LIVE_TAMPER_TEST=1 (root + BPF-LSM required)")
	}
	run := func(mode string, enforce bool) {
		t.Run(mode, func(t *testing.T) {
			s, err := NewTamperSensor(uint32(os.Getpid()), enforce)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if enforce && !s.Enforcing() {
				t.Fatalf("enforcement not active: %v", s.EnforceError())
			}

			// Protect the sensor's own programs, as the agent does.
			s.ProtectObjects(s.OwnObjects())

			var mu sync.Mutex
			var alerts []TamperAlert
			go s.Run(func(a TamperAlert) { mu.Lock(); alerts = append(alerts, a); mu.Unlock() })
			time.Sleep(300 * time.Millisecond)

			pid := fmt.Sprint(os.Getpid())
			// SIGCONT is harmless if enforcement were to fail.
			killOut, killErr := exec.Command("sh", "-c", "kill -s CONT "+pid).CombinedOutput()
			// Same signal to a non-main thread id (the old tracepoint sensor
			// only knew the tgid).
			tid := otherThreadID(t)
			tidOut, tidErr := exec.Command("sh", "-c", "kill -s CONT "+tid).CombinedOutput()
			bpfOut, bpfErr := exec.Command("bpftool", "prog", "show").CombinedOutput()
			time.Sleep(500 * time.Millisecond)

			mu.Lock()
			defer mu.Unlock()
			kinds := map[string]bool{}
			blocked := false
			signalActors := map[string]bool{}
			for _, a := range alerts {
				kinds[a.Kind] = true
				if a.Kind == "signal" {
					signalActors[a.Fields["actor_pid"]] = true
				}
				blocked = blocked || a.Fields["blocked"] == "true"
				t.Logf("alert: [%s] %s blocked=%s", a.Severity, a.Message, a.Fields["blocked"])
			}
			if !kinds["signal"] {
				t.Error("no signal alert")
			}
			if len(signalActors) < 2 {
				t.Errorf("thread-id signal not reported (signal actors: %v)", signalActors)
			}
			if !kinds["bpf-management"] {
				t.Error("no bpf-management alert")
			}
			if enforce {
				if killErr == nil {
					t.Errorf("kill was not denied: %s", killOut)
				}
				if tidErr == nil {
					t.Errorf("thread-id kill was not denied: %s", tidOut)
				}
				if bpfErr == nil {
					t.Errorf("bpftool prog show was not denied: %s", firstLine(bpfOut))
				}
				if !blocked {
					t.Error("no alert marked blocked")
				}
			} else {
				if killErr != nil || tidErr != nil {
					t.Errorf("detect mode must not block kill: %v %s / %v %s", killErr, killOut, tidErr, tidOut)
				}
				if bpfErr != nil {
					t.Errorf("detect mode must not block bpftool: %v", bpfErr)
				}
				if blocked {
					t.Error("detect mode reported blocked=true")
				}
			}
		})
	}
	run("detect", false)
	run("enforce", true)
}

func firstLine(b []byte) string {
	return strings.SplitN(string(b), "\n", 2)[0]
}

// otherThreadID returns a thread id of this process other than its tgid.
func otherThreadID(t *testing.T) string {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/task")
	if err != nil {
		t.Fatal(err)
	}
	self := fmt.Sprint(os.Getpid())
	for _, e := range ents {
		if e.Name() != self {
			return e.Name()
		}
	}
	t.Skip("single-threaded")
	return ""
}
