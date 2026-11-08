package distributor

import (
	"testing"

	"github.com/Nextron-Labs/aurora-linux/lib/enrichment"
)

func TestEnrichParentFieldsIgnoresInvalidParentProcessID(t *testing.T) {
	c, err := enrichment.NewCorrelator(4)
	if err != nil {
		t.Fatalf("NewCorrelator() error = %v", err)
	}
	c.Store(42, &enrichment.ProcessInfo{
		PID:         42,
		Image:       "/sbin/init",
		CommandLine: "init",
	})

	fields := enrichment.DataFieldsMap{
		"ParentProcessId": enrichment.NewStringValue("42x"),
	}

	enrichParentFields(fields, c)

	if v := fields.Value("ParentImage"); v.Valid {
		t.Fatalf("ParentImage should not be set for invalid ParentProcessId, got %q", v.String)
	}
	if v := fields.Value("ParentCommandLine"); v.Valid {
		t.Fatalf("ParentCommandLine should not be set for invalid ParentProcessId, got %q", v.String)
	}
}

func TestEnrichImageFromCacheIgnoresInvalidProcessID(t *testing.T) {
	c, err := enrichment.NewCorrelator(4)
	if err != nil {
		t.Fatalf("NewCorrelator() error = %v", err)
	}
	c.Store(123, &enrichment.ProcessInfo{
		PID:   123,
		Image: "/usr/bin/python3",
	})

	fields := enrichment.DataFieldsMap{
		"ProcessId": enrichment.NewStringValue("123abc"),
	}

	enrichImageFromCache(fields, c)

	if v := fields.Value("Image"); v.Valid {
		t.Fatalf("Image should not be set for invalid ProcessId, got %q", v.String)
	}
}
