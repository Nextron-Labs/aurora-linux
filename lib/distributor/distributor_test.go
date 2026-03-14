package distributor

import (
	"testing"
	"time"

	"github.com/Nextron-Labs/aurora-linux/lib/enrichment"
	"github.com/Nextron-Labs/aurora-linux/lib/provider"
)

func TestRegisterConsumerDoesNotBlockWhileConsumerHandlesEvent(t *testing.T) {
	d := New(enrichment.NewEventEnricher(), nil)

	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})

	d.RegisterConsumer(&blockingConsumer{
		started: started,
		release: release,
		done:    done,
	})

	go d.HandleEvent(&testEvent{
		id: provider.EventIdentifier{ProviderName: "Test", EventID: 1},
	})

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("consumer did not start handling event")
	}

	registerDone := make(chan struct{})
	go func() {
		d.RegisterConsumer(&noopConsumer{})
		close(registerDone)
	}()

	select {
	case <-registerDone:
		// expected: registration should not wait for callback completion
	case <-time.After(500 * time.Millisecond):
		t.Fatal("RegisterConsumer() blocked on in-flight HandleEvent")
	}

	close(release)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("blocking consumer did not finish")
	}
}

type blockingConsumer struct {
	started chan<- struct{}
	release <-chan struct{}
	done    chan<- struct{}
}

func (c *blockingConsumer) Name() string { return "blocking" }
func (c *blockingConsumer) Initialize() error {
	return nil
}
func (c *blockingConsumer) HandleEvent(event provider.Event) error {
	close(c.started)
	<-c.release
	close(c.done)
	return nil
}
func (c *blockingConsumer) Close() error { return nil }

type noopConsumer struct{}

func (c *noopConsumer) Name() string { return "noop" }
func (c *noopConsumer) Initialize() error {
	return nil
}
func (c *noopConsumer) HandleEvent(event provider.Event) error { return nil }
func (c *noopConsumer) Close() error                           { return nil }

type testEvent struct {
	id provider.EventIdentifier
}

func (e *testEvent) ID() provider.EventIdentifier                { return e.id }
func (e *testEvent) Process() uint32                             { return 0 }
func (e *testEvent) Source() string                              { return "test" }
func (e *testEvent) Time() time.Time                             { return time.Unix(0, 0) }
func (e *testEvent) Value(fieldname string) enrichment.DataValue { return enrichment.DataValue{} }
func (e *testEvent) ForEach(fn func(key string, value string))   {}
