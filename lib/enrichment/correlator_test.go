package enrichment

import (
	"testing"
)

func TestCorrelatorStoreAndLookup(t *testing.T) {
	c, err := NewCorrelator(100)
	if err != nil {
		t.Fatal(err)
	}

	info := &ProcessInfo{
		PID:         1234,
		Image:       "/usr/bin/bash",
		CommandLine: "bash -c echo test",
		User:        "root",
	}

	c.Store(1234, info)

	got := c.Lookup(1234)
	if got == nil {
		t.Fatal("Lookup returned nil")
	}
	if got.Image != "/usr/bin/bash" {
		t.Errorf("Image = %q, want /usr/bin/bash", got.Image)
	}
	if got.CommandLine != "bash -c echo test" {
		t.Errorf("CommandLine = %q, want 'bash -c echo test'", got.CommandLine)
	}
}

func TestCorrelatorLookupMiss(t *testing.T) {
	c, err := NewCorrelator(100)
	if err != nil {
		t.Fatal(err)
	}

	got := c.Lookup(9999)
	if got != nil {
		t.Errorf("expected nil for missing PID, got %v", got)
	}
}

func TestCorrelatorEviction(t *testing.T) {
	c, err := NewCorrelator(2) // tiny cache
	if err != nil {
		t.Fatal(err)
	}

	c.Store(1, &ProcessInfo{PID: 1, Image: "a"})
	c.Store(2, &ProcessInfo{PID: 2, Image: "b"})
	c.Store(3, &ProcessInfo{PID: 3, Image: "c"})

	// PID 1 should have been evicted
	if c.Lookup(1) != nil {
		t.Error("PID 1 should have been evicted")
	}

	// PID 3 should be present
	if c.Lookup(3) == nil {
		t.Error("PID 3 should be present")
	}
}

func TestCorrelatorWithZeroSize(t *testing.T) {
	_, err := NewCorrelator(0)
	if err == nil {
		t.Fatal("NewCorrelator(0) expected error")
	}
}

func TestCorrelatorWithNegativeSize(t *testing.T) {
	_, err := NewCorrelator(-1)
	if err == nil {
		t.Fatal("NewCorrelator(-1) expected error")
	}
}

func TestCorrelatorLen(t *testing.T) {
	c, err := NewCorrelator(100)
	if err != nil {
		t.Fatal(err)
	}

	if c.Len() != 0 {
		t.Errorf("Len() = %d, want 0 for empty cache", c.Len())
	}

	c.Store(1, &ProcessInfo{PID: 1, Image: "a"})
	c.Store(2, &ProcessInfo{PID: 2, Image: "b"})

	if c.Len() != 2 {
		t.Errorf("Len() = %d, want 2", c.Len())
	}
}

func TestCorrelatorUpdate(t *testing.T) {
	c, err := NewCorrelator(100)
	if err != nil {
		t.Fatal(err)
	}

	// Store initial value
	c.Store(1234, &ProcessInfo{PID: 1234, Image: "/usr/bin/bash"})

	// Update with new value
	c.Store(1234, &ProcessInfo{PID: 1234, Image: "/usr/bin/zsh"})

	got := c.Lookup(1234)
	if got == nil {
		t.Fatal("Lookup returned nil")
	}
	if got.Image != "/usr/bin/zsh" {
		t.Errorf("Image = %q, want /usr/bin/zsh (updated)", got.Image)
	}
}
