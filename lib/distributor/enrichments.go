package distributor

import (
	"strconv"

	"github.com/Nextron-Labs/aurora-linux/lib/enrichment"
)

// RegisterLinuxEnrichments registers all Linux-specific enrichment functions
// keyed by provider name and event ID.
func RegisterLinuxEnrichments(enricher *enrichment.EventEnricher, correlator *enrichment.Correlator) {
	// Process creation (EventID 1): enrich parent fields from correlator
	enricher.Register("LinuxEBPF:1", func(fields enrichment.DataFieldsMap) {
		enrichParentFields(fields, correlator)
	})

	// File event (EventID 11): enrich Image from correlator if missing
	enricher.Register("LinuxEBPF:11", func(fields enrichment.DataFieldsMap) {
		enrichImageFromCache(fields, correlator)
	})

	// Network connection (EventID 3): enrich Image from correlator if missing
	enricher.Register("LinuxEBPF:3", func(fields enrichment.DataFieldsMap) {
		enrichImageFromCache(fields, correlator)
	})
}

// enrichParentFields fills ParentImage and ParentCommandLine from the
// correlation cache if they are not already set by the provider.
func enrichParentFields(fields enrichment.DataFieldsMap, correlator *enrichment.Correlator) {
	if correlator == nil {
		return
	}

	ppidVal := fields.Value("ParentProcessId")
	if !ppidVal.Valid {
		return
	}

	// ParentImage already set by provider (from /proc fallback) — check if
	// we have a better value from the cache.
	parentImage := fields.Value("ParentImage")
	parentCmdLine := fields.Value("ParentCommandLine")

	ppid64, err := strconv.ParseUint(ppidVal.String, 10, 32)
	if err != nil {
		return
	}
	ppid := uint32(ppid64)

	info := correlator.Lookup(ppid)
	if info == nil {
		return
	}

	// Prefer cached values — they represent the image/cmdline at exec time.
	if !parentImage.Valid || parentImage.String == "" {
		fields.AddField("ParentImage", info.Image)
	}
	if !parentCmdLine.Valid || parentCmdLine.String == "" {
		fields.AddField("ParentCommandLine", info.CommandLine)
	}
}

// enrichImageFromCache fills Image from the correlator cache if the provider
// failed to read /proc/PID/exe (process may have exited).
func enrichImageFromCache(fields enrichment.DataFieldsMap, correlator *enrichment.Correlator) {
	if correlator == nil {
		return
	}

	imageVal := fields.Value("Image")
	if imageVal.Valid && imageVal.String != "" {
		return
	}

	pidVal := fields.Value("ProcessId")
	if !pidVal.Valid {
		return
	}

	pid64, err := strconv.ParseUint(pidVal.String, 10, 32)
	if err != nil {
		return
	}
	pid := uint32(pid64)

	info := correlator.Lookup(pid)
	if info != nil && info.Image != "" {
		fields.AddField("Image", info.Image)
	}
}
