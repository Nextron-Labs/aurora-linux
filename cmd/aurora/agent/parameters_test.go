package agent

import "testing"

func TestDefaultParametersEnableSigmaNoCollapseWS(t *testing.T) {
	params := DefaultParameters()
	if !params.SigmaNoCollapseWS {
		t.Fatal("SigmaNoCollapseWS should default to true")
	}
}

func TestResolveAuditMode(t *testing.T) {
	cases := []struct {
		name    string
		mode    string
		logs    []string
		want    string
		wantErr bool
	}{
		{name: "default is ebpf", want: AuditModeEBPF},
		{name: "audit-log alone keeps the pre-audit-mode behaviour", logs: []string{"/var/log/audit/audit.log"}, want: AuditModeAuditd},
		{name: "both", mode: "both", want: AuditModeBoth},
		{name: "explicit ebpf wins over audit-log", mode: "ebpf", logs: []string{"x"}, want: AuditModeEBPF},
		{name: "explicit auditd", mode: "auditd", want: AuditModeAuditd},
		{name: "off", mode: "OFF", want: AuditModeOff},
		{name: "invalid", mode: "bogus", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := DefaultParameters()
			p.AuditMode = tc.mode
			p.AuditLogFiles = tc.logs
			got, err := p.ResolveAuditMode()
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("mode = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestResolveTamperMode(t *testing.T) {
	for in, want := range map[string]string{"": TamperDetect, "detect": TamperDetect, "ENFORCE": TamperEnforce, "off": TamperOff} {
		p := DefaultParameters()
		p.TamperProtection = in
		got, err := p.ResolveTamperMode()
		if err != nil || got != want {
			t.Errorf("%q: got %q, %v want %q", in, got, err, want)
		}
	}
	p := DefaultParameters()
	p.TamperProtection = "paranoid"
	if _, err := p.ResolveTamperMode(); err == nil {
		t.Error("invalid mode accepted")
	}
}

func TestLogsourceServices(t *testing.T) {
	if got := logsourceServices(AuditModeEBPF, false); len(got) != 1 || got[0] != "auditd" {
		t.Errorf("ebpf only: %v", got)
	}
	if got := logsourceServices(AuditModeOff, false); got == nil || len(got) != 0 {
		t.Errorf("off must be an empty non-nil list, got %#v", got)
	}
	got := logsourceServices(AuditModeEBPF, true)
	found := map[string]bool{}
	for _, s := range got {
		found[s] = true
	}
	for _, want := range []string{"auditd", "syslog", "sshd", "cron"} {
		if !found[want] {
			t.Errorf("missing service %s in %v", want, got)
		}
	}
}
