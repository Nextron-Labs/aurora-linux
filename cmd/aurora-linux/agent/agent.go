package agent

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/nicholasgasior/aurora-linux/lib/consumer/sigma"
	"github.com/nicholasgasior/aurora-linux/lib/distributor"
	"github.com/nicholasgasior/aurora-linux/lib/enrichment"
	"github.com/nicholasgasior/aurora-linux/lib/logging"
	ebpfprovider "github.com/nicholasgasior/aurora-linux/lib/provider/ebpf"
	log "github.com/sirupsen/logrus"
)

// Agent orchestrates the lifecycle of the Aurora Linux EDR agent.
type Agent struct {
	params     Parameters
	listener   *ebpfprovider.Listener
	dist       *distributor.Distributor
	consumer   *sigma.SigmaConsumer
	correlator *enrichment.Correlator
	enricher   *enrichment.EventEnricher
	statsStop  chan struct{}
	statsDone  chan struct{}
	logFile    *os.File
}

// New creates a new agent from the given parameters.
func New(params Parameters) *Agent {
	return &Agent{params: params}
}

// Run initializes all components and starts the event processing loop.
// It blocks until a SIGINT or SIGTERM is received.
func (a *Agent) Run() error {
	// Configure logging
	if err := a.configureLogging(); err != nil {
		return fmt.Errorf("configuring logging: %w", err)
	}
	defer a.closeLogFile()

	a.printWelcomeBanner()
	log.Info("Aurora Linux EDR Agent starting")
	log.WithFields(log.Fields{
		"rules":             a.params.RuleDirs,
		"ringbuf_pages":     a.params.RingBufSizePages,
		"correlation_cache": a.params.CorrelationCacheSize,
	}).Info("Configuration")

	if a.params.RingBufSizePages != DefaultParameters().RingBufSizePages {
		log.WithField("ringbuf_pages", a.params.RingBufSizePages).Warn(
			"--ringbuf-size is currently informational and not applied at runtime",
		)
	}

	// Create correlator
	var err error
	a.correlator, err = enrichment.NewCorrelator(a.params.CorrelationCacheSize)
	if err != nil {
		return fmt.Errorf("creating correlator: %w", err)
	}

	// Create enricher and register enrichments
	a.enricher = enrichment.NewEventEnricher()
	distributor.RegisterLinuxEnrichments(a.enricher, a.correlator)

	// Create distributor
	a.dist = distributor.New(a.enricher, a.correlator)

	// Create and initialize Sigma consumer
	sigmaLogger := log.StandardLogger()
	a.consumer = sigma.New(sigma.Config{
		RuleDirs:      a.params.RuleDirs,
		Logger:        sigmaLogger,
		ThrottleRate:  a.params.ThrottleRate,
		ThrottleBurst: a.params.ThrottleBurst,
	})

	if err := a.consumer.Initialize(); err != nil {
		return fmt.Errorf("initializing Sigma consumer: %w", err)
	}
	a.dist.RegisterConsumer(a.consumer)

	// Load Sigma rules if rule directories are specified
	if len(a.params.RuleDirs) > 0 {
		if err := a.consumer.InitializeWithRules(a.params.RuleDirs); err != nil {
			return fmt.Errorf("loading Sigma rules: %w", err)
		}
	}

	// Create and initialize eBPF listener
	a.listener = ebpfprovider.NewListener(a.correlator)

	// Enable all sources
	a.listener.AddSource(ebpfprovider.SourceProcessExec)
	a.listener.AddSource(ebpfprovider.SourceFileCreate)
	a.listener.AddSource(ebpfprovider.SourceNetConnect)

	if err := a.listener.Initialize(); err != nil {
		return fmt.Errorf("initializing eBPF listener: %w", err)
	}

	log.Info("eBPF listener initialized, starting event collection")

	// Start stats reporting
	if a.params.StatsInterval > 0 {
		a.statsStop = make(chan struct{})
		a.statsDone = make(chan struct{})
		go a.reportStats(a.statsStop, a.statsDone)
	}

	// Handle signals for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	// Start event collection in a goroutine
	doneCh := make(chan struct{})
	go func() {
		a.listener.SendEvents(a.dist.HandleEvent)
		close(doneCh)
	}()

	// Wait for signal
	sig := <-sigCh
	log.WithField("signal", sig).Info("Received shutdown signal")

	// Graceful shutdown
	a.shutdown()
	<-doneCh

	log.Info("Aurora Linux EDR Agent stopped")
	return nil
}

// shutdown performs a graceful shutdown of all components.
func (a *Agent) shutdown() {
	log.Info("Shutting down...")

	if a.statsStop != nil {
		close(a.statsStop)
		a.statsStop = nil
	}
	if a.statsDone != nil {
		<-a.statsDone
		a.statsDone = nil
	}

	if a.listener != nil {
		if err := a.listener.Close(); err != nil {
			log.WithError(err).Warn("Failed to close eBPF listener cleanly")
		}
	}
	if a.consumer != nil {
		if err := a.consumer.Close(); err != nil {
			log.WithError(err).Warn("Failed to close Sigma consumer cleanly")
		}
	}

	var processed, matches, lost uint64
	if a.dist != nil {
		processed = a.dist.Processed()
	}
	if a.consumer != nil {
		matches = a.consumer.Matches()
	}
	if a.listener != nil {
		lost = a.listener.LostEvents()
	}

	log.WithFields(log.Fields{
		"events_processed": processed,
		"sigma_matches":    matches,
		"events_lost":      lost,
	}).Info("Final statistics")
}

// reportStats periodically logs processing statistics.
func (a *Agent) reportStats(stop <-chan struct{}, done chan<- struct{}) {
	ticker := time.NewTicker(time.Duration(a.params.StatsInterval) * time.Second)
	defer ticker.Stop()
	defer close(done)

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
		}

		if a.listener == nil || a.dist == nil || a.consumer == nil {
			continue
		}

		lost := a.listener.LostEvents()
		processed := a.dist.Processed()
		matches := a.consumer.Matches()

		fields := log.Fields{
			"events_processed": processed,
			"sigma_matches":    matches,
			"events_lost":      lost,
		}

		if processed > 0 && lost > 0 {
			lostPct := float64(lost) / float64(processed+lost) * 100
			fields["lost_pct"] = fmt.Sprintf("%.3f%%", lostPct)
			if lostPct > 1.0 {
				log.WithFields(fields).Warn(
					"Event loss exceeds 1%; reduce event load or tune BPF map sizes at build/deploy time",
				)
				continue
			}
		}

		log.WithFields(fields).Info("Processing statistics")
	}
}

// configureLogging sets up the log formatter and output.
func (a *Agent) configureLogging() error {
	if a.params.JSONOutput {
		log.SetFormatter(&logging.JSONFormatter{})
	} else {
		log.SetFormatter(&logging.TextFormatter{})
	}

	if a.params.Verbose {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}

	if a.params.LogFile != "" {
		f, err := openSecureLogFile(a.params.LogFile)
		if err != nil {
			return err
		}
		a.logFile = f
		log.SetOutput(f)
	}

	return nil
}

func (a *Agent) closeLogFile() {
	if a.logFile == nil {
		return
	}

	f := a.logFile
	a.logFile = nil
	log.SetOutput(os.Stdout)
	if err := f.Close(); err != nil {
		log.WithError(err).Warn("Failed to close log file cleanly")
	}
}

func (a *Agent) printWelcomeBanner() {
	// Keep JSON log mode machine-friendly by skipping non-JSON banner text.
	if a.params.JSONOutput {
		return
	}

	version := strings.TrimSpace(a.params.Version)
	if version == "" {
		version = "dev"
	}
	if !strings.HasPrefix(strings.ToLower(version), "v") {
		version = "v" + version
	}

	lines := []string{
		"  __    _     ___   ___   ___    __",
		" / /\\  | | | | |_) / / \\ | |_)  / /\\",
		"/_/--\\ \\_\\_/ |_| \\ \\_\\_/ |_| \\ /_/--\\",
		"",
		"Real-Time Sigma Matching on Linux via eBPF",
		"",
		fmt.Sprintf("(c) Florian Roth, 2026, %s", version),
	}

	width := 0
	for _, line := range lines {
		if len(line) > width {
			width = len(line)
		}
	}

	var b strings.Builder
	b.WriteString(strings.Repeat("=", width))
	b.WriteString("\n")
	for _, line := range lines {
		b.WriteString(line)
		b.WriteString(strings.Repeat(" ", width-len(line)))
		b.WriteString("\n")
	}
	b.WriteString(strings.Repeat("=", width))
	b.WriteString("\n")

	_, _ = fmt.Fprintln(log.StandardLogger().Out, b.String())
}

// openSecureLogFile opens a logfile path in append mode while refusing
// symlink targets and non-regular files.
func openSecureLogFile(path string) (*os.File, error) {
	path = filepath.Clean(path)

	fd, err := syscall.Open(
		path,
		syscall.O_CREAT|syscall.O_WRONLY|syscall.O_APPEND|syscall.O_NOFOLLOW,
		0600,
	)
	if err != nil {
		return nil, fmt.Errorf("opening logfile %q: %w", path, err)
	}

	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("opening logfile %q: failed to wrap file descriptor", path)
	}

	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("stat logfile %q: %w", path, err)
	}
	if !st.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("logfile %q must be a regular file", path)
	}

	return f, nil
}
