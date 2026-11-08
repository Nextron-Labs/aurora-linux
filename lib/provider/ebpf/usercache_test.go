package ebpf

import (
	"os/user"
	"strconv"
	"testing"
)

func TestNewUserCacheSuccess(t *testing.T) {
	cache, err := NewUserCache(100)
	if err != nil {
		t.Fatalf("NewUserCache(100) error = %v", err)
	}
	if cache == nil {
		t.Fatal("NewUserCache(100) returned nil")
	}
	if cache.cache == nil {
		t.Fatal("NewUserCache(100).cache is nil")
	}
}

func TestNewUserCacheInvalidSize(t *testing.T) {
	// LRU cache with size <= 0 should fail
	_, err := NewUserCache(0)
	if err == nil {
		t.Fatal("NewUserCache(0) expected error")
	}

	_, err = NewUserCache(-1)
	if err == nil {
		t.Fatal("NewUserCache(-1) expected error")
	}
}

func TestUserCacheLookupCurrentUser(t *testing.T) {
	cache, err := NewUserCache(10)
	if err != nil {
		t.Fatalf("NewUserCache error = %v", err)
	}

	// Look up current user
	currentUser, err := user.Current()
	if err != nil {
		t.Skipf("Cannot determine current user: %v", err)
	}

	uid64, err := strconv.ParseUint(currentUser.Uid, 10, 32)
	if err != nil {
		t.Skipf("Cannot parse UID: %v", err)
	}
	uid := uint32(uid64)

	got := cache.Lookup(uid)
	if got != currentUser.Username {
		t.Fatalf("Lookup(%d) = %q, want %q", uid, got, currentUser.Username)
	}
}

func TestUserCacheLookupRoot(t *testing.T) {
	cache, err := NewUserCache(10)
	if err != nil {
		t.Fatalf("NewUserCache error = %v", err)
	}

	// UID 0 is root on Unix systems
	got := cache.Lookup(0)
	if got != "root" {
		t.Fatalf("Lookup(0) = %q, want root", got)
	}
}

func TestUserCacheLookupNonExistentUser(t *testing.T) {
	cache, err := NewUserCache(10)
	if err != nil {
		t.Fatalf("NewUserCache error = %v", err)
	}

	// Very high UID unlikely to exist
	nonExistentUID := uint32(4294967290)
	got := cache.Lookup(nonExistentUID)

	// Should return the numeric UID as string
	expected := strconv.FormatUint(uint64(nonExistentUID), 10)
	if got != expected {
		t.Fatalf("Lookup(%d) = %q, want %q", nonExistentUID, got, expected)
	}
}

func TestUserCacheLookupCaching(t *testing.T) {
	cache, err := NewUserCache(10)
	if err != nil {
		t.Fatalf("NewUserCache error = %v", err)
	}

	// First lookup
	first := cache.Lookup(0)

	// Second lookup should return cached value
	second := cache.Lookup(0)

	if first != second {
		t.Fatalf("Cached lookup mismatch: first=%q second=%q", first, second)
	}
}

func TestUserCacheLookupMultipleUsers(t *testing.T) {
	cache, err := NewUserCache(10)
	if err != nil {
		t.Fatalf("NewUserCache error = %v", err)
	}

	// Lookup root
	root := cache.Lookup(0)
	if root != "root" {
		t.Fatalf("Lookup(0) = %q, want root", root)
	}

	// Lookup current user
	currentUser, err := user.Current()
	if err != nil {
		t.Skipf("Cannot determine current user: %v", err)
	}

	uid64, err := strconv.ParseUint(currentUser.Uid, 10, 32)
	if err != nil {
		t.Skipf("Cannot parse UID: %v", err)
	}

	current := cache.Lookup(uint32(uid64))
	if current != currentUser.Username {
		t.Fatalf("Lookup(current UID) = %q, want %q", current, currentUser.Username)
	}

	// Verify both are still in cache
	if cache.Lookup(0) != root {
		t.Fatal("Root lookup changed after adding current user")
	}
}

func TestUserCacheLRUEviction(t *testing.T) {
	// Create a very small cache to test LRU eviction
	cache, err := NewUserCache(2)
	if err != nil {
		t.Fatalf("NewUserCache error = %v", err)
	}

	// Add more entries than capacity
	cache.Lookup(0)             // root
	cache.Lookup(65534)         // nobody (or numeric)
	cache.Lookup(4294967290)    // non-existent (numeric)

	// The LRU cache should have evicted the oldest entry
	// We're just verifying it doesn't panic and still returns sensible values
	got := cache.Lookup(4294967290)
	expected := "4294967290"
	if got != expected {
		t.Fatalf("Lookup after eviction = %q, want %q", got, expected)
	}
}

func TestUserCacheLookupRepeatedCalls(t *testing.T) {
	cache, err := NewUserCache(10)
	if err != nil {
		t.Fatalf("NewUserCache error = %v", err)
	}

	// Multiple rapid lookups should be consistent
	for i := 0; i < 100; i++ {
		got := cache.Lookup(0)
		if got != "root" {
			t.Fatalf("Iteration %d: Lookup(0) = %q, want root", i, got)
		}
	}
}
