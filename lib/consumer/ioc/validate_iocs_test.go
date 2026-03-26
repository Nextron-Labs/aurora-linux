package ioc

import (
	"os"
	"testing"
)

// TestValidateRealC2IOCs loads the production C2 IOC file and verifies
// all entries are accepted. This catches regressions where validation
// rejects previously-valid indicators.
func TestValidateRealC2IOCs(t *testing.T) {
	const path = "/opt/aurora-linux/resources/iocs/c2-iocs.txt"
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skipf("production IOC file not found: %s", path)
	}

	domains, ips, err := loadC2IOCs(path, true)
	if err != nil {
		t.Fatalf("loadC2IOCs() error = %v", err)
	}

	total := len(domains) + len(ips)
	t.Logf("Loaded %d C2 IOCs (%d domains, %d IPs)", total, len(domains), len(ips))

	if total == 0 {
		t.Fatal("expected at least some C2 IOCs to load")
	}

	// Verify scored entries parsed correctly
	for key, entry := range domains {
		if entry.score < 0 || entry.score > 100 {
			t.Errorf("domain %q has out-of-range score %d", key, entry.score)
		}
	}
	for key, entry := range ips {
		if entry.score < 0 || entry.score > 100 {
			t.Errorf("IP %q has out-of-range score %d", key, entry.score)
		}
	}
}

// TestValidateRealFilenameIOCs loads the production filename IOC file
// and verifies all entries are accepted.
func TestValidateRealFilenameIOCs(t *testing.T) {
	const path = "/opt/aurora-linux/resources/iocs/filename-iocs.txt"
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skipf("production IOC file not found: %s", path)
	}

	entries, err := loadFilenameIOCs(path, true)
	if err != nil {
		t.Fatalf("loadFilenameIOCs() error = %v", err)
	}

	t.Logf("Loaded %d filename IOC entries", len(entries))

	if len(entries) == 0 {
		t.Fatal("expected at least some filename IOCs to load")
	}

	// Check all entries have valid scores and compiled patterns
	withFP := 0
	for _, entry := range entries {
		if entry.score < 0 || entry.score > 100 {
			t.Errorf("line %d: pattern %q has out-of-range score %d", entry.line, entry.rawPattern, entry.score)
		}
		if entry.pattern == nil {
			t.Errorf("line %d: pattern %q did not compile", entry.line, entry.rawPattern)
		}
		if entry.falsePositive != nil {
			withFP++
		}
	}
	t.Logf("  %d entries have false-positive exclusion patterns", withFP)
}
