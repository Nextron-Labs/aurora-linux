package agent

import (
	"fmt"
	"github.com/Nextron-Labs/aurora-linux/lib/consumer/sigma"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	ebpfprovider "github.com/Nextron-Labs/aurora-linux/lib/provider/ebpf"
	log "github.com/sirupsen/logrus"
)

// Tamper protection modes for Parameters.TamperProtection.
const (
	TamperOff     = "off"
	TamperDetect  = "detect"
	TamperEnforce = "enforce"

	tamperStatePath    = "/run/aurora-linux/state"
	tamperScanInterval = 10 * time.Second
	canaryInterval     = 30 * time.Second
	canaryTimeout      = 5 * time.Second
	// canaryMaxBacklog bounds how long a round waits for a backlogged
	// reader to reach the canary's events before reporting pipeline lag.
	canaryMaxBacklog  = 60 * time.Second
	lossCheckInterval = 5 * time.Second
	lossAlertInterval = 30 * time.Second
	lossHighThreshold = 1000
	// blindRestartAfter consecutive silent canary rounds make Aurora exit
	// non-zero so the service manager restarts it with fresh eBPF programs.
	blindRestartAfter = 2
)

// ResolveTamperMode returns the validated tamper protection mode.
func (p Parameters) ResolveTamperMode() (string, error) {
	switch m := strings.ToLower(strings.TrimSpace(p.TamperProtection)); m {
	case "":
		return TamperDetect, nil
	case TamperOff, TamperDetect, TamperEnforce:
		return m, nil
	default:
		return "", fmt.Errorf("--tamper-protection must be one of: off, detect, enforce (got %q)", p.TamperProtection)
	}
}

// tamperGuard bundles the anti-tamper components.
type tamperGuard struct {
	prevStart time.Time
	logger    *log.Logger
	sensor    *ebpfprovider.TamperSensor
	watcher   *ebpfprovider.BPFWatcher
	canary    *ebpfprovider.Canary
	state     ebpfprovider.RunState
	stop      chan struct{}
	wg        sync.WaitGroup
	exit      func(code int)
}

// alert writes a tamper alert to the same sinks as Sigma matches.
func (g *tamperGuard) alert(a ebpfprovider.TamperAlert) {
	fields := log.Fields{
		"alert_type":      "tamper",
		"tamper_kind":     a.Kind,
		"tamper_severity": a.Severity,
		"timestamp":       a.Time.Format(time.RFC3339Nano),
	}
	for k, v := range a.Fields {
		if k == "actor_cmdline" {
			v = sigma.SanitizeCmdline(v) // never log secrets passed on a command line
		}
		fields[k] = v
	}
	level := log.ErrorLevel
	switch a.Severity {
	case ebpfprovider.SeverityInfo:
		level = log.InfoLevel
	case ebpfprovider.SeverityMedium:
		level = log.WarnLevel
	}
	entry := log.Entry{Logger: g.logger, Data: fields}
	entry.Log(level, "Aurora tamper alert: "+a.Message)
}

// startTamperProtection hardens the process and starts the sensors. It never
// fails startup: problems are logged and the available layers keep running.
// hostPID is Aurora's pid as the kernel sees it (root pid namespace).
func (a *Agent) startTamperProtection(mode string, logger *log.Logger, hostPID uint32) {
	if mode == TamperOff {
		return
	}
	for _, err := range ebpfprovider.HardenSelf() {
		log.WithError(err).Warn("Self-hardening step failed")
	}
	// Signals whose default action would kill Aurora but that nothing
	// legitimate sends it; attempts are still reported by the sensor.
	signal.Ignore(syscall.SIGHUP, syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGALRM, syscall.SIGVTALRM,
		syscall.SIGPROF, syscall.SIGTTIN, syscall.SIGTTOU, syscall.SIGTSTP)

	g := &tamperGuard{
		logger: logger,
		canary: &ebpfprovider.Canary{AuroraPid: hostPID},
		state:  ebpfprovider.RunState{Path: tamperStatePath},
		stop:   make(chan struct{}),
		exit:   os.Exit,
	}
	prev := g.state.Begin()

	sensor, err := ebpfprovider.NewTamperSensor(hostPID, mode == TamperEnforce)
	if err != nil {
		log.WithError(err).Warn("Tamper sensor unavailable; signal/ptrace/bpf tamper detection disabled")
	} else {
		g.sensor = sensor
		if mode == TamperEnforce {
			if e := sensor.EnforceError(); e != nil {
				log.WithError(e).Warn("Tamper enforcement unavailable; falling back to detection only")
			} else {
				log.Info("Tamper enforcement active (BPF-LSM): signals, ptrace, control files and Aurora's eBPF objects are protected")
			}
		}
	}

	if prev.SelfExit != "" {
		g.alert(ebpfprovider.TamperAlert{
			Time: time.Now(), Kind: "previous-self-restart", Severity: ebpfprovider.SeverityHigh,
			Message: fmt.Sprintf("the previous Aurora instance (pid %d) exited to restart its sensors (reason: %s)",
				prev.SelfExitPid, prev.SelfExit),
			Fields: map[string]string{"previous_pid": fmt.Sprint(prev.SelfExitPid), "reason": prev.SelfExit},
		})
	}
	if prev.UncleanPid != 0 {
		a2 := ebpfprovider.TamperAlert{
			Time: time.Now(), Kind: "unclean-previous-exit", Severity: ebpfprovider.SeverityHigh,
			Message: fmt.Sprintf("the previous Aurora instance (pid %d) did not shut down cleanly: it may have been killed", prev.UncleanPid),
			Fields:  map[string]string{"previous_pid": fmt.Sprint(prev.UncleanPid)},
		}
		if sensor != nil {
			if f := sensor.PreviousFatal(); f != nil {
				a2.Severity = ebpfprovider.SeverityCritical
				a2.Message = fmt.Sprintf("the previous Aurora instance was killed with %s by %s (pid %d, uid %d)",
					f.Signal, f.ActorComm, f.ActorPid, f.ActorUID)
				a2.Fields["actor_pid"] = fmt.Sprint(f.ActorPid)
				a2.Fields["actor_uid"] = fmt.Sprint(f.ActorUID)
				a2.Fields["actor_comm"] = f.ActorComm
				a2.Fields["signal"] = f.Signal
				a2.Fields["killed_at"] = f.Time.UTC().Format(time.RFC3339Nano)
			}
		}
		g.alert(a2)
	}

	// Protect Aurora's own BPF objects and control files.
	own := a.listener.OwnObjects()
	if sensor != nil {
		own.Merge(sensor.OwnObjects())
		sensor.ProtectObjects(own)
		sensor.ProtectInodes(ebpfprovider.ControlFileKeys())
		g.wg.Add(1)
		go func() { defer g.wg.Done(); sensor.Run(g.alert) }()
	}

	g.watcher = ebpfprovider.NewBPFWatcher(own.Programs)
	g.prevStart = prev.PrevStart
	g.wg.Add(3)
	go g.scanLoop()
	go g.canaryLoop(a.listener)
	go g.lossLoop(a.listener)

	a.tamper.Store(g)
	log.WithField("mode", mode).Info("Tamper protection started")
}

func (g *tamperGuard) scanLoop() {
	defer g.wg.Done()
	baseline := true
	t := time.NewTicker(tamperScanInterval)
	defer t.Stop()
	for {
		// At start-up, programs loaded since the previous instance started
		// (e.g. during a restart gap) are reported, older ones inventoried.
		if err := g.watcher.Scan(baseline, g.prevStart, g.alert); err != nil {
			log.WithError(err).Debug("eBPF program inventory failed")
		}
		baseline = false
		select {
		case <-g.stop:
			return
		case <-t.C:
		}
	}
}

// lossLoop turns kernel ring-buffer overflows into alerts. Flooding the
// agent with events is a way to blind it; the lost counters tell us.
func (g *tamperGuard) lossLoop(l *ebpfprovider.Listener) {
	defer g.wg.Done()
	var last uint64
	var pending uint64
	var lastAlert time.Time
	t := time.NewTicker(lossCheckInterval)
	defer t.Stop()
	for {
		select {
		case <-g.stop:
			return
		case <-t.C:
		}
		total := l.LostEvents()
		if g.sensor != nil {
			total += g.sensor.Lost()
		}
		if total > last {
			pending += total - last
		}
		last = total
		if pending == 0 || time.Since(lastAlert) < lossAlertInterval {
			continue
		}
		sev := ebpfprovider.SeverityMedium
		if pending >= lossHighThreshold {
			sev = ebpfprovider.SeverityHigh
		}
		g.alert(ebpfprovider.TamperAlert{
			Time: time.Now(), Kind: "event-loss", Severity: sev,
			Message: fmt.Sprintf("%d kernel events were dropped (ring buffer overflow): an event flood can hide malicious activity", pending),
			Fields:  map[string]string{"events_lost": fmt.Sprint(pending), "events_lost_total": fmt.Sprint(total)},
		})
		pending, lastAlert = 0, time.Now()
	}
}

func (g *tamperGuard) canaryLoop(l *ebpfprovider.Listener) {
	defer g.wg.Done()
	select {
	case <-g.stop:
		return
	case <-time.After(10 * time.Second):
	}
	silent := map[string]int{}
	t := time.NewTicker(canaryInterval)
	defer t.Stop()
	for {
		lostBefore := l.LostEvents()
		res, err := g.canary.Check(l.ActiveSources(), canaryTimeout, canaryMaxBacklog, l.SourceProgress, g.stop)
		missing := res.Missing
		lossy := l.LostEvents() != lostBefore
		if err == nil && len(res.Lagging) > 0 {
			// Not blind: the reader is still working through older events.
			// Detection is delayed, which matters, but restarting would
			// only make it worse.
			g.alert(ebpfprovider.TamperAlert{
				Time: time.Now(), Kind: "pipeline-lag", Severity: ebpfprovider.SeverityHigh,
				Message: fmt.Sprintf("event processing is more than %s behind for %v: detections are delayed (host overloaded or event flood)",
					canaryMaxBacklog, res.Lagging),
				Fields: map[string]string{"event_sources": fmt.Sprint(res.Lagging)},
			})
		}
		switch {
		case err != nil:
			log.WithError(err).Debug("Tamper canary could not run")
		case len(missing) > 0 && lossy:
			// Kernel events were dropped during the round (flood): the
			// canary may have been among them. Report, but do not treat it
			// as proof of blinding (an event flood must not be able to
			// force restart loops). event-loss alerts cover the flood.
			log.WithField("missing", missing).Debug("Tamper canary inconclusive: events were lost during the round")
		default:
			if len(missing) == 0 && len(res.Lagging) == 0 {
				log.WithField("sources", l.ActiveSources()).Debug("Tamper canary passed")
			}
			now := map[string]bool{}
			for _, s := range missing {
				now[s] = true
				silent[s]++
				g.alert(ebpfprovider.TamperAlert{
					Time: time.Now(), Kind: "blind-source", Severity: ebpfprovider.SeverityCritical,
					Message: fmt.Sprintf("event source %s delivered no canary event: monitoring is blind (eBPF program detached or altered?)", s),
					Fields:  map[string]string{"event_source": s, "consecutive_failures": fmt.Sprint(silent[s])},
				})
				if silent[s] >= blindRestartAfter {
					log.Error("Event source still blind; exiting so the service manager can restart Aurora with fresh eBPF programs")
					g.state.SelfExit("blind-source")
					g.exit(75)
				}
			}
			for s := range silent {
				if !now[s] {
					delete(silent, s)
				}
			}
		}
		select {
		case <-g.stop:
			return
		case <-t.C:
		}
	}
}

func (g *tamperGuard) close() {
	close(g.stop)
	if g.sensor != nil {
		g.sensor.Close()
	}
	g.wg.Wait()
	g.state.End()
}
