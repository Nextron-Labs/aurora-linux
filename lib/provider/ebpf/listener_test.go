package ebpf

import (
	"errors"
	"strings"
	"testing"
)

func TestInitializeDisablesFailedMonitorAndContinues(t *testing.T) {
	l := NewListener(nil)
	l.enableExec = true
	l.enableFile = true
	l.enableTime = true
	l.enableNet = true

	l.initExecFn = func() error { return nil }
	l.initFileFn = func() error { return errors.New("file init failed") }
	l.initTimeFn = func() error { return nil }
	l.initNetFn = func() error { return nil }

	if err := l.Initialize(); err != nil {
		t.Fatalf("Initialize() returned unexpected error: %v", err)
	}

	if !l.enableExec {
		t.Fatal("exec source should remain enabled")
	}
	if l.enableFile {
		t.Fatal("file source should be disabled after init failure")
	}
	if !l.enableTime {
		t.Fatal("filetime source should remain enabled")
	}
	if !l.enableNet {
		t.Fatal("net source should remain enabled")
	}
}

func TestInitializeFailsWhenAllRequestedMonitorsFail(t *testing.T) {
	l := NewListener(nil)
	l.enableExec = true
	l.enableTime = true
	l.enableNet = true

	l.initExecFn = func() error { return errors.New("exec failed") }
	l.initTimeFn = func() error { return errors.New("filetime failed") }
	l.initNetFn = func() error { return errors.New("net failed") }

	err := l.Initialize()
	if err == nil {
		t.Fatal("Initialize() expected error when all requested monitors fail")
	}

	if !strings.Contains(err.Error(), "failed to initialize any eBPF monitor") {
		t.Fatalf("expected aggregate initialization error, got: %v", err)
	}
	if l.enableExec {
		t.Fatal("exec source should be disabled after init failure")
	}
	if l.enableTime {
		t.Fatal("filetime source should be disabled after init failure")
	}
	if l.enableNet {
		t.Fatal("net source should be disabled after init failure")
	}
}

func TestAddSourceEnablesFiletimeMonitor(t *testing.T) {
	l := NewListener(nil)

	if err := l.AddSource(SourceFileTime); err != nil {
		t.Fatalf("AddSource() error = %v", err)
	}

	if !l.enableTime {
		t.Fatal("filetime source should be enabled")
	}
}
