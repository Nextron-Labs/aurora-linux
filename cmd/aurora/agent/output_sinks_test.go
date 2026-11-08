package agent

import (
	"bytes"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

func TestFormattedOutputHookFireWritesFormattedEntry(t *testing.T) {
	var buf bytes.Buffer
	hook := &formattedOutputHook{
		formatter: &log.JSONFormatter{DisableTimestamp: true},
		writer:    &buf,
	}

	entry := &log.Entry{
		Level:   log.WarnLevel,
		Message: "test alert",
		Data:    log.Fields{"key": "value"},
	}

	if err := hook.Fire(entry); err != nil {
		t.Fatalf("Fire() error = %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, `"msg":"test alert"`) {
		t.Fatalf("expected msg in output, got %q", out)
	}
	if !strings.Contains(out, `"key":"value"`) {
		t.Fatalf("expected data field in output, got %q", out)
	}
	if !strings.HasSuffix(out, "\n") {
		t.Fatalf("expected newline-terminated output, got %q", out)
	}
}

func TestFormattedOutputHookFireNilHookIsNoop(t *testing.T) {
	var hook *formattedOutputHook
	entry := &log.Entry{Level: log.InfoLevel, Message: "test"}
	// Should not panic.
	if err := hook.Fire(entry); err != nil {
		t.Fatalf("Fire() on nil hook error = %v", err)
	}
}

func TestFormattedOutputHookLevelsReturnsAll(t *testing.T) {
	hook := &formattedOutputHook{}
	levels := hook.Levels()
	if len(levels) == 0 {
		t.Fatal("Levels() returned empty slice")
	}
	// Should include at least info, warn, error.
	found := make(map[log.Level]bool)
	for _, l := range levels {
		found[l] = true
	}
	for _, want := range []log.Level{log.InfoLevel, log.WarnLevel, log.ErrorLevel} {
		if !found[want] {
			t.Fatalf("Levels() missing %v", want)
		}
	}
}

func TestNetworkWriterTCPWriteAndClose(t *testing.T) {
	// Start a TCP listener.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	defer ln.Close()

	var received bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.Copy(&received, conn)
	}()

	w, err := newNetworkWriter("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("newNetworkWriter() error = %v", err)
	}

	payload := []byte("alert line 1\nalert line 2\n")
	n, err := w.Write(payload)
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if n != len(payload) {
		t.Fatalf("Write() = %d, want %d", n, len(payload))
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	wg.Wait()

	if got := received.String(); got != string(payload) {
		t.Fatalf("received %q, want %q", got, string(payload))
	}
}

func TestNetworkWriterUDPWriteAndClose(t *testing.T) {
	// Start a UDP listener.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.ListenPacket() error = %v", err)
	}
	defer pc.Close()

	var received bytes.Buffer
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		buf := make([]byte, 4096)
		pc.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		received.Write(buf[:n])
	}()

	w, err := newNetworkWriter("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("newNetworkWriter() error = %v", err)
	}

	payload := []byte("udp alert\n")
	n, err := w.Write(payload)
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if n != len(payload) {
		t.Fatalf("Write() = %d, want %d", n, len(payload))
	}

	<-readDone

	if got := received.String(); got != string(payload) {
		t.Fatalf("received %q, want %q", got, string(payload))
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestNetworkWriterCloseIsIdempotent(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	defer ln.Close()

	// Accept connections to avoid connection refused.
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	w, err := newNetworkWriter("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("newNetworkWriter() error = %v", err)
	}

	// Force connection establishment.
	w.Write([]byte("x"))

	if err := w.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	// Second close should be a no-op.
	if err := w.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}

func TestNetworkWriterReconnectsAfterServerDrop(t *testing.T) {
	// Start first listener.
	ln1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	addr := ln1.Addr().String()

	// Accept and immediately close to simulate server drop.
	go func() {
		conn, err := ln1.Accept()
		if err != nil {
			return
		}
		conn.Close()
	}()

	w, err := newNetworkWriter("tcp", addr)
	if err != nil {
		t.Fatalf("newNetworkWriter() error = %v", err)
	}
	defer w.Close()

	// First write establishes connection.
	w.Write([]byte("first\n"))

	// Close first listener and give it a moment.
	ln1.Close()
	time.Sleep(50 * time.Millisecond)

	// Start new listener on same address.
	ln2, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("could not rebind %s: %v", addr, err)
	}
	defer ln2.Close()

	var received bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := ln2.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.Copy(&received, conn)
	}()

	// Write after reconnect.
	payload := []byte("after reconnect\n")
	n, err := w.Write(payload)
	if err != nil {
		t.Fatalf("Write() after reconnect error = %v", err)
	}
	if n != len(payload) {
		t.Fatalf("Write() = %d, want %d", n, len(payload))
	}

	w.Close()
	wg.Wait()

	if got := received.String(); got != string(payload) {
		t.Fatalf("received %q after reconnect, want %q", got, string(payload))
	}
}

func TestNewNetworkWriterRejectsUnsupportedProtocol(t *testing.T) {
	_, err := newNetworkWriter("unix", "/tmp/test.sock")
	if err == nil {
		t.Fatal("expected error for unsupported network protocol")
	}
	if !strings.Contains(err.Error(), "unsupported network") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNetworkWriterLazyConnect(t *testing.T) {
	// Writer should not connect until first Write().
	w, err := newNetworkWriter("tcp", "127.0.0.1:1")
	if err != nil {
		t.Fatalf("newNetworkWriter() error = %v", err)
	}

	// conn should be nil before any write.
	w.mu.Lock()
	if w.conn != nil {
		w.mu.Unlock()
		t.Fatal("expected nil conn before first Write()")
	}
	w.mu.Unlock()
}

func TestResolveOutputFormatDefaults(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		jsonFall bool
		want     string
		wantErr  bool
	}{
		{name: "empty_no_json", value: "", jsonFall: false, want: outputFormatSyslog},
		{name: "empty_json_fallback", value: "", jsonFall: true, want: outputFormatJSON},
		{name: "explicit_syslog", value: "syslog", jsonFall: true, want: outputFormatSyslog},
		{name: "explicit_json", value: "json", jsonFall: false, want: outputFormatJSON},
		{name: "invalid", value: "xml", jsonFall: false, want: "", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveOutputFormat(tc.value, tc.jsonFall)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("resolveOutputFormat(%q, %v) = %q, want %q", tc.value, tc.jsonFall, got, tc.want)
			}
		})
	}
}

func TestFormatterForOutputFormat(t *testing.T) {
	jsonF := formatterForOutputFormat(outputFormatJSON)
	if jsonF == nil {
		t.Fatal("expected non-nil formatter for json")
	}

	syslogF := formatterForOutputFormat(outputFormatSyslog)
	if syslogF == nil {
		t.Fatal("expected non-nil formatter for syslog")
	}

	// Unknown should default to syslog.
	defaultF := formatterForOutputFormat("unknown")
	if defaultF == nil {
		t.Fatal("expected non-nil default formatter")
	}
}
