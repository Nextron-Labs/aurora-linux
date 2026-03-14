package distributor

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/Nextron-Labs/aurora-linux/lib/enrichment"
	"github.com/Nextron-Labs/aurora-linux/lib/provider"
	log "github.com/sirupsen/logrus"
)

// EventConsumer processes normalized events after enrichment.
type EventConsumer interface {
	Name() string
	Initialize() error
	HandleEvent(event provider.Event) error
	Close() error
}

// Distributor receives events from providers, applies enrichment, and
// forwards them to registered consumers.
type Distributor struct {
	mu        sync.RWMutex
	enricher  *enrichment.EventEnricher
	consumers []EventConsumer
	// consumersView stores an immutable []EventConsumer snapshot for
	// allocation-free reads on the hot path.
	consumersView atomic.Value
	correlator    *enrichment.Correlator

	processed atomic.Uint64
}

// New creates a new Distributor with the given enricher and correlator.
func New(enricher *enrichment.EventEnricher, correlator *enrichment.Correlator) *Distributor {
	d := &Distributor{
		enricher:   enricher,
		correlator: correlator,
	}
	d.consumersView.Store([]EventConsumer(nil))
	return d
}

// RegisterConsumer adds a consumer to receive events.
func (d *Distributor) RegisterConsumer(c EventConsumer) {
	d.mu.Lock()
	d.consumers = append(d.consumers, c)
	snapshot := append([]EventConsumer(nil), d.consumers...)
	d.mu.Unlock()
	d.consumersView.Store(snapshot)
}

// HandleEvent is the callback passed to providers. It enriches the event
// and forwards it to all consumers.
func (d *Distributor) HandleEvent(event provider.Event) {
	consumers := d.snapshotConsumers()

	// Apply enrichments based on provider + event ID
	key := enrichmentKey(event.ID())
	if d.enricher != nil {
		if fields, ok := event.(interface {
			Fields() enrichment.DataFieldsMap
		}); ok {
			d.enricher.Enrich(key, fields.Fields())
		}
	}

	// Cache process data for correlation
	d.cacheProcessData(event)

	// Forward to all consumers
	for _, c := range consumers {
		if err := safeHandleEvent(c, event); err != nil {
			log.WithFields(log.Fields{
				"consumer": c.Name(),
				"error":    err,
			}).Error("Consumer failed to handle event")
		}
	}

	d.processed.Add(1)
}

func (d *Distributor) snapshotConsumers() []EventConsumer {
	if cur, ok := d.consumersView.Load().([]EventConsumer); ok {
		return cur
	}

	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.consumers
}

// cacheProcessData stores process info for parent correlation on process_creation events.
func (d *Distributor) cacheProcessData(event provider.Event) {
	if d.correlator == nil {
		return
	}

	// Only cache process_creation events (EventID 1)
	if event.ID().EventID != 1 {
		return
	}

	info := &enrichment.ProcessInfo{
		PID:              event.Process(),
		Image:            event.Value("Image").String,
		CommandLine:      event.Value("CommandLine").String,
		User:             event.Value("User").String,
		CurrentDirectory: event.Value("CurrentDirectory").String,
	}
	d.correlator.Store(event.Process(), info)
}

// Processed returns the number of events processed.
func (d *Distributor) Processed() uint64 {
	return d.processed.Load()
}

// Correlator returns the correlator for use by enrichment functions.
func (d *Distributor) Correlator() *enrichment.Correlator {
	return d.correlator
}

// safeHandleEvent wraps a consumer's HandleEvent in panic recovery so that
// a single misbehaving consumer cannot crash the entire event pipeline.
func safeHandleEvent(c EventConsumer, event provider.Event) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic in consumer %s: %v", c.Name(), r)
		}
	}()
	return c.HandleEvent(event)
}

func enrichmentKey(id provider.EventIdentifier) string {
	return fmt.Sprintf("%s:%d", id.ProviderName, id.EventID)
}
