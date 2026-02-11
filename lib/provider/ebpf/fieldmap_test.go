package ebpf

import (
	"strings"
	"testing"
)

func TestJoinCmdline(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		wantCmdline string
		wantTrunc   bool
	}{
		{
			name:        "normal command",
			input:       []byte("python3\x00-c\x00import os\x00"),
			wantCmdline: "python3 -c import os",
			wantTrunc:   false,
		},
		{
			name:        "single arg",
			input:       []byte("ls\x00"),
			wantCmdline: "ls",
			wantTrunc:   false,
		},
		{
			name:        "empty",
			input:       []byte{},
			wantCmdline: "",
			wantTrunc:   false,
		},
		{
			name:        "multi args with spaces",
			input:       []byte("base64\x00-d\x00/tmp/encoded_payload.b64\x00"),
			wantCmdline: "base64 -d /tmp/encoded_payload.b64",
			wantTrunc:   false,
		},
		{
			name:        "no trailing NUL",
			input:       []byte("echo\x00hello"),
			wantCmdline: "echo hello",
			wantTrunc:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, trunc := joinCmdline(tt.input)
			if got != tt.wantCmdline {
				t.Errorf("joinCmdline() cmdline = %q, want %q", got, tt.wantCmdline)
			}
			if trunc != tt.wantTrunc {
				t.Errorf("joinCmdline() truncated = %v, want %v", trunc, tt.wantTrunc)
			}
		})
	}
}

func TestJoinCmdlineTruncated(t *testing.T) {
	// Create a buffer exactly at maxCmdlineBytes
	data := make([]byte, maxCmdlineBytes)
	for i := range data {
		data[i] = 'A'
	}

	got, trunc := joinCmdline(data)
	if !trunc {
		t.Error("expected truncated=true for full buffer")
	}
	if !strings.HasSuffix(got, " ...(truncated)") {
		t.Errorf("expected truncation suffix, got: %q", got[len(got)-30:])
	}
}

func TestNullTermStr(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		maxLen int
		want   string
	}{
		{
			name:   "normal",
			input:  []byte{'h', 'e', 'l', 'l', 'o', 0, 'x', 'x'},
			maxLen: 8,
			want:   "hello",
		},
		{
			name:   "no null",
			input:  []byte{'h', 'e', 'l', 'l', 'o'},
			maxLen: 5,
			want:   "hello",
		},
		{
			name:   "empty",
			input:  []byte{0, 'x', 'x'},
			maxLen: 3,
			want:   "",
		},
		{
			name:   "maxLen zero",
			input:  []byte{'h', 'e', 'l', 'l', 'o'},
			maxLen: 0,
			want:   "hello",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := nullTermStr(tt.input, tt.maxLen)
			if got != tt.want {
				t.Errorf("nullTermStr() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildExecFieldsMap(t *testing.T) {
	fields := buildExecFieldsMap(
		1234, // pid
		1000, // ppid
		0,    // uid
		"/usr/bin/bash",
		"/usr/bin/bash",
		"bash -c ./exploit.sh",
		false,
		"/tmp",
		"0",
		"root",
		"/bin/systemd",
		"systemd",
	)

	checks := map[string]string{
		"Image":             "/usr/bin/bash",
		"CommandLine":       "bash -c ./exploit.sh",
		"ParentImage":       "/bin/systemd",
		"ParentCommandLine": "systemd",
		"User":              "root",
		"LogonId":           "0",
		"CurrentDirectory":  "/tmp",
		"ProcessId":         "1234",
		"ParentProcessId":   "1000",
	}

	for key, expected := range checks {
		v := fields.Value(key)
		if !v.Valid {
			t.Errorf("field %q not found", key)
			continue
		}
		if v.String != expected {
			t.Errorf("field %q = %q, want %q", key, v.String, expected)
		}
	}

	// CommandLineTruncated should not be set
	v := fields.Value("CommandLineTruncated")
	if v.Valid {
		t.Error("CommandLineTruncated should not be set when not truncated")
	}
}

func TestBuildExecFieldsMapTruncated(t *testing.T) {
	fields := buildExecFieldsMap(
		1234, 1000, 0,
		"/usr/bin/bash", "/usr/bin/bash",
		"long command ...(truncated)",
		true, // truncated
		"/tmp", "0", "root",
		"/bin/systemd", "systemd",
	)

	v := fields.Value("CommandLineTruncated")
	if !v.Valid || v.String != "true" {
		t.Errorf("CommandLineTruncated = %v, want valid=true, string=true", v)
	}
}

func TestBuildFileFieldsMap(t *testing.T) {
	fields := buildFileFieldsMap(
		9100, 0,
		"/etc/cron.d/updater",
		"/bin/bash",
		"root",
		0x241,
	)

	checks := map[string]string{
		"TargetFilename": "/etc/cron.d/updater",
		"Image":          "/bin/bash",
		"User":           "root",
		"ProcessId":      "9100",
	}

	for key, expected := range checks {
		v := fields.Value(key)
		if !v.Valid {
			t.Errorf("field %q not found", key)
			continue
		}
		if v.String != expected {
			t.Errorf("field %q = %q, want %q", key, v.String, expected)
		}
	}
}

func TestBuildNetFieldsMap(t *testing.T) {
	fields := buildNetFieldsMap(
		7500, 33,
		"/bin/bash", "www-data",
		"192.168.1.100", 45678,
		"10.0.0.1", 4242,
		true, // initiated
	)

	checks := map[string]string{
		"Image":           "/bin/bash",
		"DestinationIp":   "10.0.0.1",
		"DestinationPort": "4242",
		"SourceIp":        "192.168.1.100",
		"SourcePort":      "45678",
		"Initiated":       "true",
		"User":            "www-data",
		"ProcessId":       "7500",
		"Protocol":        "tcp",
	}

	for key, expected := range checks {
		v := fields.Value(key)
		if !v.Valid {
			t.Errorf("field %q not found", key)
			continue
		}
		if v.String != expected {
			t.Errorf("field %q = %q, want %q", key, v.String, expected)
		}
	}
}

func TestBuildNetFieldsMapInbound(t *testing.T) {
	fields := buildNetFieldsMap(
		100, 0,
		"/usr/sbin/sshd", "root",
		"192.168.1.1", 22,
		"10.0.0.5", 54321,
		false, // not initiated (inbound)
	)

	v := fields.Value("Initiated")
	if !v.Valid || v.String != "false" {
		t.Errorf("Initiated = %v, want false", v)
	}
}

func TestFormatIPv4(t *testing.T) {
	// IPv4-mapped-v6: ::ffff:10.0.0.1
	var addr [16]byte
	addr[10] = 0xff
	addr[11] = 0xff
	addr[12] = 10
	addr[13] = 0
	addr[14] = 0
	addr[15] = 1

	got := formatIPv4(addr)
	if got != "10.0.0.1" {
		t.Errorf("formatIPv4() = %q, want %q", got, "10.0.0.1")
	}
}

func TestFormatIPv4Loopback(t *testing.T) {
	var addr [16]byte
	addr[10] = 0xff
	addr[11] = 0xff
	addr[12] = 127
	addr[13] = 0
	addr[14] = 0
	addr[15] = 1

	got := formatIPv4(addr)
	if got != "127.0.0.1" {
		t.Errorf("formatIPv4() = %q, want %q", got, "127.0.0.1")
	}
}

func TestFormatIPv6AllZero(t *testing.T) {
	var addr [16]byte

	got := formatIPv6(addr)
	if got != "::" {
		t.Errorf("formatIPv6() = %q, want %q", got, "::")
	}
}

func TestFormatIPv6Compressed(t *testing.T) {
	addr := [16]byte{
		0x20, 0x01, // 2001
		0x0d, 0xb8, // db8
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x01, // 1
	}

	got := formatIPv6(addr)
	if got != "2001:db8::1" {
		t.Errorf("formatIPv6() = %q, want %q", got, "2001:db8::1")
	}
}
