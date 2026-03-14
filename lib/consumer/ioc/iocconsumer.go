package ioc

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Nextron-Labs/aurora-linux/lib/provider"
	log "github.com/sirupsen/logrus"
)

var (
	sensitiveValueFieldNames = []string{
		"password", "passwd", "secret", "token", "api_key", "apikey",
	}
	cmdlineInlineSecretPattern = regexp.MustCompile(`(?i)(password|passwd|pwd|token|secret|api[_-]?key)(\s*[:=]\s*)([^\s"'` + "`" + `]+)`)
	cmdlineFlagSecretPattern   = regexp.MustCompile(`(?i)(--?(?:password|passwd|pwd|token|secret|api[_-]?key))(?:\s+|=)([^\s"'` + "`" + `]+)`)
)

var (
	filenameIOCMatchFields = []string{"Image", "ParentImage", "TargetFilename", "CommandLine", "ParentCommandLine"}
	c2IOCMatchFields       = []string{"DestinationIp", "DestinationHostname"}
)

// Config holds IOC consumer configuration.
type Config struct {
	FilenameIOCPath string
	C2IOCPath       string

	FilenameIOCRequired bool
	C2IOCRequired       bool

	Logger *log.Logger
}

// Consumer matches events against IOC lists.
type Consumer struct {
	cfg Config

	filenameEntries []filenameIOCEntry
	c2Domains       map[string]struct{}
	c2IPs           map[string]struct{}

	logger *log.Logger

	matches atomic.Uint64
}

// New creates a new IOC consumer.
func New(cfg Config) *Consumer {
	return &Consumer{cfg: cfg, logger: cfg.Logger}
}

// Name returns the consumer name.
func (c *Consumer) Name() string { return "IOCConsumer" }

// Initialize loads IOC files.
func (c *Consumer) Initialize() error {
	filenamePath, c2Path, filenameRequired, c2Required := resolveIOCPaths(c.cfg.FilenameIOCPath, c.cfg.C2IOCPath)
	c.cfg.FilenameIOCPath = filenamePath
	c.cfg.C2IOCPath = c2Path

	filenameEntries, err := loadFilenameIOCs(c.cfg.FilenameIOCPath, filenameRequired || c.cfg.FilenameIOCRequired)
	if err != nil {
		return err
	}
	c2Domains, c2IPs, err := loadC2IOCs(c.cfg.C2IOCPath, c2Required || c.cfg.C2IOCRequired)
	if err != nil {
		return err
	}

	c.filenameEntries = filenameEntries
	c.c2Domains = c2Domains
	c.c2IPs = c2IPs

	log.WithFields(log.Fields{
		"filename_iocs": len(c.filenameEntries),
		"c2_domains":    len(c.c2Domains),
		"c2_ips":        len(c.c2IPs),
		"filename_path": strings.TrimSpace(c.cfg.FilenameIOCPath),
		"c2_path":       strings.TrimSpace(c.cfg.C2IOCPath),
	}).Info("IOC sets loaded")

	return nil
}

// HandleEvent evaluates an event against loaded IOC entries.
func (c *Consumer) HandleEvent(event provider.Event) error {
	for _, key := range filenameIOCMatchFields {
		value := strings.TrimSpace(event.Value(key).String)
		if value == "" {
			continue
		}
		for _, entry := range c.filenameEntries {
			if !entry.pattern.MatchString(value) {
				continue
			}
			if entry.falsePositive != nil && entry.falsePositive.MatchString(value) {
				continue
			}
			c.matches.Add(1)
			c.emitFilenameMatch(event, key, value, entry)
		}
	}

	for _, key := range c2IOCMatchFields {
		value := strings.TrimSpace(event.Value(key).String)
		if value == "" {
			continue
		}

		switch key {
		case "DestinationIp":
			if ip := normalizeIP(value); ip != "" {
				if _, ok := c.c2IPs[ip]; ok {
					c.matches.Add(1)
					c.emitC2Match(event, key, value, ip)
				}
			}
		case "DestinationHostname":
			host := normalizeDomain(value)
			if host == "" {
				continue
			}
			if _, ok := c.c2Domains[host]; ok {
				c.matches.Add(1)
				c.emitC2Match(event, key, value, host)
			}
		}
	}

	return nil
}

func (c *Consumer) emitFilenameMatch(event provider.Event, field, value string, entry filenameIOCEntry) {
	fields := log.Fields{
		"ioc_type":       "filename",
		"ioc_field":      field,
		"ioc_value":      sanitizeFieldForLogging(field, value),
		"ioc_regex":      entry.rawPattern,
		"ioc_score":      entry.score,
		"ioc_line":       entry.line,
		"ioc_source":     filepath.Base(strings.TrimSpace(c.cfg.FilenameIOCPath)),
		"event_provider": event.ID().ProviderName,
		"event_id":       event.ID().EventID,
		"event_source":   event.Source(),
		"event_process":  event.Process(),
		"event_time":     event.Time().UTC().Format(time.RFC3339Nano),
	}
	if entry.rawFalsePositive != "" {
		fields["ioc_false_positive_regex"] = entry.rawFalsePositive
	}
	addEventFields(fields, event)

	entryLog := log.Entry{Logger: effectiveLogger(c.logger), Data: fields}
	entryLog.Log(logLevelForFilenameScore(entry.score), "IOC match")
}

func (c *Consumer) emitC2Match(event provider.Event, field, value, indicator string) {
	fields := log.Fields{
		"ioc_type":       "c2",
		"ioc_field":      field,
		"ioc_value":      sanitizeFieldForLogging(field, value),
		"ioc_indicator":  indicator,
		"ioc_source":     filepath.Base(strings.TrimSpace(c.cfg.C2IOCPath)),
		"event_provider": event.ID().ProviderName,
		"event_id":       event.ID().EventID,
		"event_source":   event.Source(),
		"event_process":  event.Process(),
		"event_time":     event.Time().UTC().Format(time.RFC3339Nano),
	}
	addEventFields(fields, event)

	entryLog := log.Entry{Logger: effectiveLogger(c.logger), Data: fields}
	entryLog.Log(log.ErrorLevel, "IOC match")
}

func addEventFields(fields log.Fields, event provider.Event) {
	event.ForEach(func(key, value string) {
		safeValue := sanitizeFieldForLogging(key, value)
		if _, exists := fields[key]; exists {
			key = "event_" + key
			if _, exists := fields[key]; exists {
				return
			}
		}
		fields[key] = safeValue
	})
}

func effectiveLogger(logger *log.Logger) *log.Logger {
	if logger != nil {
		return logger
	}
	return log.StandardLogger()
}

func logLevelForFilenameScore(score int) log.Level {
	switch {
	case score >= 80:
		return log.ErrorLevel
	case score >= 60:
		return log.WarnLevel
	default:
		return log.InfoLevel
	}
}

func sanitizeFieldForLogging(key, value string) string {
	keyLower := strings.ToLower(key)
	for _, marker := range sensitiveValueFieldNames {
		if strings.Contains(keyLower, marker) {
			return "[REDACTED]"
		}
	}

	switch key {
	case "CommandLine", "ParentCommandLine":
		value = cmdlineInlineSecretPattern.ReplaceAllString(value, `$1$2[REDACTED]`)
		value = cmdlineFlagSecretPattern.ReplaceAllString(value, `$1 [REDACTED]`)
	}

	return value
}

// Matches returns the number of IOC matches emitted.
func (c *Consumer) Matches() uint64 {
	return c.matches.Load()
}

// Close closes consumer resources.
func (c *Consumer) Close() error { return nil }

func normalizeDomain(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimSuffix(value, ".")
	return value
}

func normalizeIP(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if ip, err := netip.ParseAddr(value); err == nil {
		return ip.String()
	}
	return ""
}

func defaultIOCPaths() (filenamePath, c2Path string) {
	exe, err := os.Executable()
	if err != nil {
		return "", ""
	}
	dir := filepath.Dir(exe)
	return filepath.Join(dir, "resources", "iocs", "filename-iocs.txt"), filepath.Join(dir, "resources", "iocs", "c2-iocs.txt")
}

func resolveIOCPaths(filenamePath, c2Path string) (resolvedFilename, resolvedC2 string, filenameRequired, c2Required bool) {
	resolvedFilename = strings.TrimSpace(filenamePath)
	resolvedC2 = strings.TrimSpace(c2Path)
	filenameRequired = resolvedFilename != ""
	c2Required = resolvedC2 != ""

	if resolvedFilename != "" && resolvedC2 != "" {
		return resolvedFilename, resolvedC2, filenameRequired, c2Required
	}

	defaultFilename, defaultC2 := defaultIOCPaths()
	if resolvedFilename == "" {
		resolvedFilename = defaultFilename
	}
	if resolvedC2 == "" {
		resolvedC2 = defaultC2
	}

	return resolvedFilename, resolvedC2, filenameRequired, c2Required
}

func missingIOCSourceError(kind, path string, err error) error {
	return fmt.Errorf("opening %s IOC file %q: %w", kind, path, err)
}
