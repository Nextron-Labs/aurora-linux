package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Nextron-Labs/aurora-linux/lib/consumer/ioc"
	"github.com/Nextron-Labs/aurora-linux/lib/consumer/sigma"
	"github.com/Nextron-Labs/aurora-linux/lib/distributor"
	"github.com/Nextron-Labs/aurora-linux/lib/enrichment"
	"github.com/Nextron-Labs/aurora-linux/lib/logging"
	"github.com/Nextron-Labs/aurora-linux/lib/provider"
	ebpfprovider "github.com/Nextron-Labs/aurora-linux/lib/provider/ebpf"
	log "github.com/sirupsen/logrus"
)

// Agent orchestrates the lifecycle of the Aurora Linux EDR agent.
type Agent struct {
	params     Parameters
	listener   *ebpfprovider.Listener
	dist       *distributor.Distributor
	consumer   *sigma.SigmaConsumer
	ioc        *ioc.Consumer
	correlator *enrichment.Correlator
	enricher   *enrichment.EventEnricher
	statsStop  chan struct{}
	statsDone  chan struct{}
	logFile    *os.File
	closers    []func() error
	pprofSrv   *http.Server
	pprofAddr  string
}

// New creates a new agent from the given parameters.
func New(params Parameters) *Agent {
	return &Agent{params: params}
}

// Run initializes all components and starts the event processing loop.
// It blocks until a SIGINT or SIGTERM is received.
func (a *Agent) Run() error {
	// Configure logging
	sigmaLogger, err := a.configureLogging()
	if err != nil {
		return fmt.Errorf("configuring logging: %w", err)
	}
	defer a.closeOutputs()

	if a.params.LowPrio {
		if err := syscall.Setpriority(syscall.PRIO_PROCESS, 0, 10); err != nil {
			log.WithError(err).Warn("Failed to lower process priority; continuing with default priority")
		} else {
			log.Info("Process priority lowered")
		}
	}

	a.printWelcomeBanner()
	log.Info("Aurora Linux EDR Agent starting")
	log.WithFields(log.Fields{
		"rules":             a.params.RuleDirs,
		"filename_iocs":     a.params.FilenameIOCPath,
		"c2_iocs":           a.params.C2IOCPath,
		"ringbuf_pages":     a.params.RingBufSizePages,
		"correlation_cache": a.params.CorrelationCacheSize,
		"min_level":         a.params.MinLevel,
		"sigma_no_collapse": a.params.SigmaNoCollapseWS,
		"process_exclude":   a.params.ProcessExclude,
		"trace":             a.params.Trace,
		"no_stdout":         a.params.NoStdout,
		"tcp_target":        a.params.TCPTarget,
		"udp_target":        a.params.UDPTarget,
		"pprof_listen":      a.params.PprofListen,
	}).Info("Configuration")

	if a.params.RingBufSizePages != DefaultParameters().RingBufSizePages {
		log.WithField("ringbuf_pages", a.params.RingBufSizePages).Warn(
			"--ringbuf-size is currently informational and not applied at runtime",
		)
	}

	if err := a.startPprofEndpoint(); err != nil {
		return err
	}

	// Create correlator
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
	a.consumer = sigma.New(sigma.Config{
		RuleDirs:      a.params.RuleDirs,
		Logger:        sigmaLogger,
		ThrottleRate:  a.params.ThrottleRate,
		ThrottleBurst: a.params.ThrottleBurst,
		MinLevel:      a.params.MinLevel,
		NoCollapseWS:  a.params.SigmaNoCollapseWS,
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

	a.ioc = ioc.New(ioc.Config{
		FilenameIOCPath:     a.params.FilenameIOCPath,
		C2IOCPath:           a.params.C2IOCPath,
		FilenameIOCRequired: strings.TrimSpace(a.params.FilenameIOCPath) != "",
		C2IOCRequired:       strings.TrimSpace(a.params.C2IOCPath) != "",
		Logger:              sigmaLogger,
	})
	if err := a.ioc.Initialize(); err != nil {
		return fmt.Errorf("initializing IOC consumer: %w", err)
	}
	a.dist.RegisterConsumer(a.ioc)

	// Create and initialize eBPF listener
	a.listener = ebpfprovider.NewListener(a.correlator)

	// Enable all sources (errors are checked during Initialize)
	_ = a.listener.AddSource(ebpfprovider.SourceProcessExec)
	_ = a.listener.AddSource(ebpfprovider.SourceFileCreate)
	_ = a.listener.AddSource(ebpfprovider.SourceNetConnect)
	_ = a.listener.AddSource(ebpfprovider.SourceBpfEvent)

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
		a.listener.SendEvents(func(event provider.Event) {
			if a.params.Trace {
				a.traceEvent(event)
			}
			if a.shouldExcludeEvent(event) {
				return
			}
			a.dist.HandleEvent(event)
		})
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
	a.stopPprofEndpoint()

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
	if a.ioc != nil {
		if err := a.ioc.Close(); err != nil {
			log.WithError(err).Warn("Failed to close IOC consumer cleanly")
		}
	}

	var processed, sigmaMatches, iocMatches, lost uint64
	var correlatorLen int
	if a.dist != nil {
		processed = a.dist.Processed()
	}
	if a.consumer != nil {
		sigmaMatches = a.consumer.Matches()
	}
	if a.ioc != nil {
		iocMatches = a.ioc.Matches()
	}
	if a.listener != nil {
		lost = a.listener.LostEvents()
	}
	if a.correlator != nil {
		correlatorLen = a.correlator.Len()
	}

	log.WithFields(log.Fields{
		"events_processed": processed,
		"sigma_matches":    sigmaMatches,
		"ioc_matches":      iocMatches,
		"events_lost":      lost,
		"correlator_size":  correlatorLen,
	}).Info("Final statistics")
}

func (a *Agent) startPprofEndpoint() error {
	listenAddr := strings.TrimSpace(a.params.PprofListen)
	if listenAddr == "" {
		return nil
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("starting pprof endpoint on %q: %w", listenAddr, err)
	}

	a.pprofSrv = srv
	a.pprofAddr = ln.Addr().String()
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.WithError(err).Error("pprof endpoint stopped unexpectedly")
		}
	}()

	log.WithField("pprof_listen", a.pprofAddr).Info("pprof endpoint enabled")
	return nil
}

func (a *Agent) stopPprofEndpoint() {
	if a.pprofSrv == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := a.pprofSrv.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.WithError(err).Warn("Failed to shut down pprof endpoint cleanly")
	}

	a.pprofSrv = nil
	a.pprofAddr = ""
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
		sigmaMatches := a.consumer.Matches()
		iocMatches := uint64(0)
		if a.ioc != nil {
			iocMatches = a.ioc.Matches()
		}
		correlatorLen := 0
		if a.correlator != nil {
			correlatorLen = a.correlator.Len()
		}

		fields := log.Fields{
			"events_processed": processed,
			"sigma_matches":    sigmaMatches,
			"ioc_matches":      iocMatches,
			"events_lost":      lost,
			"correlator_size":  correlatorLen,
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
func (a *Agent) configureLogging() (*log.Logger, error) {
	rollback := true
	defer func() {
		if rollback {
			a.closeOutputs()
		}
	}()

	if a.params.JSONOutput {
		log.SetFormatter(&logging.JSONFormatter{})
	} else {
		log.SetFormatter(&logging.TextFormatter{})
	}

	if a.params.Verbose || a.params.Trace {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	log.SetOutput(os.Stderr)

	matchLogger := log.New()
	matchLogger.SetLevel(log.GetLevel())
	matchLogger.SetOutput(os.Stdout)
	if a.params.JSONOutput {
		matchLogger.SetFormatter(&logging.JSONFormatter{})
	} else {
		matchLogger.SetFormatter(&logging.TextFormatter{})
	}
	if a.params.NoStdout {
		matchLogger.SetOutput(io.Discard)
	}

	if a.params.LogFile != "" {
		format, err := resolveOutputFormat(a.params.LogFileFormat, a.params.JSONOutput)
		if err != nil {
			return nil, err
		}

		f, err := openSecureLogFile(a.params.LogFile)
		if err != nil {
			return nil, err
		}
		a.logFile = f
		matchLogger.AddHook(&formattedOutputHook{
			formatter: formatterForOutputFormat(format),
			writer:    f,
		})
	}

	if a.params.TCPTarget != "" {
		format, err := resolveOutputFormat(a.params.TCPFormat, a.params.JSONOutput)
		if err != nil {
			return nil, err
		}
		w, err := newNetworkWriter("tcp", a.params.TCPTarget)
		if err != nil {
			return nil, err
		}
		a.closers = append(a.closers, w.Close)
		matchLogger.AddHook(&formattedOutputHook{
			formatter: formatterForOutputFormat(format),
			writer:    w,
		})
	}

	if a.params.UDPTarget != "" {
		format, err := resolveOutputFormat(a.params.UDPFormat, a.params.JSONOutput)
		if err != nil {
			return nil, err
		}
		w, err := newNetworkWriter("udp", a.params.UDPTarget)
		if err != nil {
			return nil, err
		}
		a.closers = append(a.closers, w.Close)
		matchLogger.AddHook(&formattedOutputHook{
			formatter: formatterForOutputFormat(format),
			writer:    w,
		})
	}

	rollback = false
	return matchLogger, nil
}

func (a *Agent) closeOutputs() {
	for i := len(a.closers) - 1; i >= 0; i-- {
		if err := a.closers[i](); err != nil {
			log.WithError(err).Warn("Failed to close output sink cleanly")
		}
	}
	a.closers = nil
	a.closeLogFile()
}

func (a *Agent) closeLogFile() {
	if a.logFile == nil {
		return
	}

	f := a.logFile
	a.logFile = nil
	log.SetOutput(os.Stderr)
	if err := f.Close(); err != nil {
		log.WithError(err).Warn("Failed to close log file cleanly")
	}
}

func (a *Agent) shouldExcludeEvent(event provider.Event) bool {
	filter := strings.ToLower(strings.TrimSpace(a.params.ProcessExclude))
	if filter == "" {
		return false
	}

	fieldsToCheck := []string{
		"Image",
		"CommandLine",
		"ParentImage",
		"ParentCommandLine",
	}

	for _, key := range fieldsToCheck {
		value := event.Value(key)
		if !value.Valid {
			continue
		}
		if strings.Contains(strings.ToLower(value.String), filter) {
			if a.params.Trace {
				log.WithFields(log.Fields{
					"process_exclude": filter,
					"matched_field":   key,
					"matched_value":   value.String,
					"event_source":    event.Source(),
				}).Debug("Excluded event due to process filter")
			}
			return true
		}
	}

	return false
}

func (a *Agent) traceEvent(event provider.Event) {
	fields := log.Fields{
		"event_provider": event.ID().ProviderName,
		"event_id":       event.ID().EventID,
		"event_source":   event.Source(),
		"event_process":  event.Process(),
		"event_time":     event.Time().UTC().Format(time.RFC3339Nano),
	}
	event.ForEach(func(key string, value string) {
		fields["event_"+key] = value
	})
	log.WithFields(fields).Debug("Trace event")
}

func (a *Agent) printWelcomeBanner() {
	// Keep JSON log mode machine-friendly by skipping non-JSON banner text.
	if a.params.JSONOutput {
		return
	}

	version := strings.TrimSpace(a.params.Version)
	if version == "" {
		version = "0.1.4"
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
