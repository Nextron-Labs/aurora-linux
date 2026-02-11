package enrichment

import (
	"testing"
	"time"
)

func TestDataFieldsMapValue(t *testing.T) {
	m := make(DataFieldsMap)
	m.AddField("Image", "/usr/bin/bash")
	m.AddField("User", "root")

	v := m.Value("Image")
	if !v.Valid || v.String != "/usr/bin/bash" {
		t.Errorf("Value(Image) = %v, want /usr/bin/bash", v)
	}

	v = m.Value("NotExist")
	if v.Valid {
		t.Error("Value(NotExist) should not be valid")
	}
}

func TestDataFieldsMapForEach(t *testing.T) {
	m := make(DataFieldsMap)
	m.AddField("A", "1")
	m.AddField("B", "2")

	count := 0
	m.ForEach(func(key, value string) {
		count++
	})
	if count != 2 {
		t.Errorf("ForEach count = %d, want 2", count)
	}
}

func TestDataFieldsMapRenameField(t *testing.T) {
	m := make(DataFieldsMap)
	m.AddField("OldKey", "value")

	ok := m.RenameField("OldKey", "NewKey")
	if !ok {
		t.Error("RenameField should return true")
	}

	v := m.Value("OldKey")
	if v.Valid {
		t.Error("OldKey should not exist after rename")
	}

	v = m.Value("NewKey")
	if !v.Valid || v.String != "value" {
		t.Errorf("NewKey = %v, want value", v)
	}

	ok = m.RenameField("NotExist", "Other")
	if ok {
		t.Error("RenameField should return false for non-existent key")
	}
}

func TestEventEnricher(t *testing.T) {
	enricher := NewEventEnricher()

	called := false
	enricher.Register("TestProvider:1", func(fields DataFieldsMap) {
		called = true
		fields.AddField("Enriched", "yes")
	})

	fields := make(DataFieldsMap)
	enricher.Enrich("TestProvider:1", fields)

	if !called {
		t.Error("manipulator was not called")
	}

	v := fields.Value("Enriched")
	if !v.Valid || v.String != "yes" {
		t.Errorf("Enriched = %v, want yes", v)
	}
}

func TestEventEnricherAllowsRegisterDuringEnrich(t *testing.T) {
	enricher := NewEventEnricher()
	enricher.Register("TestProvider:1", func(fields DataFieldsMap) {
		// Registering from inside an active Enrich call used to deadlock
		// when callbacks ran under the read lock.
		enricher.Register("TestProvider:1", func(DataFieldsMap) {})
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		enricher.Enrich("TestProvider:1", make(DataFieldsMap))
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Enrich() appears deadlocked while registering a manipulator")
	}
}
