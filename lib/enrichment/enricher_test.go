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

func TestEventEnricherMultipleManipulatorsForSameKey(t *testing.T) {
	enricher := NewEventEnricher()

	callOrder := make([]int, 0, 3)

	enricher.Register("TestProvider:1", func(fields DataFieldsMap) {
		callOrder = append(callOrder, 1)
		fields.AddField("First", "yes")
	})

	enricher.Register("TestProvider:1", func(fields DataFieldsMap) {
		callOrder = append(callOrder, 2)
		fields.AddField("Second", "yes")
	})

	enricher.Register("TestProvider:1", func(fields DataFieldsMap) {
		callOrder = append(callOrder, 3)
		// Can modify fields set by previous manipulators
		if fields.Value("First").Valid {
			fields.AddField("Third", "saw first")
		}
	})

	fields := make(DataFieldsMap)
	enricher.Enrich("TestProvider:1", fields)

	// All three manipulators should have been called
	if len(callOrder) != 3 {
		t.Fatalf("callOrder = %v, want 3 calls", callOrder)
	}

	// Order should be preserved (FIFO)
	if callOrder[0] != 1 || callOrder[1] != 2 || callOrder[2] != 3 {
		t.Fatalf("callOrder = %v, want [1 2 3]", callOrder)
	}

	// All fields should be set
	if !fields.Value("First").Valid {
		t.Error("First not set")
	}
	if !fields.Value("Second").Valid {
		t.Error("Second not set")
	}
	if !fields.Value("Third").Valid || fields.Value("Third").String != "saw first" {
		t.Errorf("Third = %v", fields.Value("Third"))
	}
}

func TestEventEnricherNoManipulatorsRegistered(t *testing.T) {
	enricher := NewEventEnricher()

	fields := make(DataFieldsMap)
	fields.AddField("Original", "value")

	// Should not panic when no manipulators registered
	enricher.Enrich("UnregisteredKey", fields)

	// Original field should be unchanged
	if !fields.Value("Original").Valid || fields.Value("Original").String != "value" {
		t.Errorf("Original = %v", fields.Value("Original"))
	}
}

func TestDataFieldsMapWithNilValue(t *testing.T) {
	m := make(DataFieldsMap)
	m["NilEntry"] = nil

	v := m.Value("NilEntry")
	if v.Valid {
		t.Error("Value for nil entry should not be valid")
	}
}

func TestDataFieldsMapForEachSkipsNilValues(t *testing.T) {
	m := make(DataFieldsMap)
	m["Good"] = NewStringValue("value")
	m["Nil"] = nil

	count := 0
	m.ForEach(func(key, value string) {
		count++
		if key == "Nil" {
			t.Error("ForEach should skip nil values")
		}
	})

	if count != 1 {
		t.Errorf("ForEach count = %d, want 1", count)
	}
}
