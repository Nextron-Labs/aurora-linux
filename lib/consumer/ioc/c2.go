package ioc

import (
	"bufio"
	"errors"
	"os"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

// c2IOCEntry holds a single C2 indicator with its optional score.
type c2IOCEntry struct {
	indicator string
	score     int
}

// defaultC2Score is the score assigned to C2 IOCs without an explicit score.
// C2 indicators are inherently high-severity, so they default to a high score.
const defaultC2Score = 80

func loadC2IOCs(path string, required bool) (map[string]c2IOCEntry, map[string]c2IOCEntry, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return map[string]c2IOCEntry{}, map[string]c2IOCEntry{}, nil
	}

	f, err := os.Open(path)
	if err != nil {
		if required {
			return nil, nil, missingIOCSourceError("c2", path, err)
		}
		if errors.Is(err, os.ErrNotExist) {
			log.WithField("path", path).Warn("C2 IOC file not found; C2 IOC matching disabled")
		} else {
			log.WithError(err).WithField("path", path).Warn("Failed to open C2 IOC file; C2 IOC matching disabled")
		}
		return map[string]c2IOCEntry{}, map[string]c2IOCEntry{}, nil
	}
	defer f.Close()

	domains := make(map[string]c2IOCEntry)
	ips := make(map[string]c2IOCEntry)

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)

	lineNo := 0
	for scanner.Scan() {
		lineNo++
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}

		if strings.ContainsAny(raw, " \t") {
			warnSkipIOCLine(path, lineNo, "unexpected whitespace")
			continue
		}

		// Parse optional score suffix: INDICATOR;SCORE
		indicator := raw
		score := defaultC2Score
		if idx := strings.LastIndex(raw, ";"); idx >= 0 {
			candidateScore := strings.TrimSpace(raw[idx+1:])
			if s, err := strconv.Atoi(candidateScore); err == nil {
				indicator = strings.TrimSpace(raw[:idx])
				score = s
			}
			// If the part after ; is not a number, treat the whole
			// line as the indicator (preserves backwards compatibility
			// for entries that might legitimately contain a semicolon).
		}

		if ip := normalizeIP(indicator); ip != "" {
			ips[ip] = c2IOCEntry{indicator: ip, score: score}
			continue
		}

		host := normalizeDomain(indicator)
		if !isLikelyDomain(host) {
			// Give a specific hint when ':' is present — likely a
			// mistyped score separator (should be ';' not ':').
			if strings.Contains(indicator, ":") {
				warnSkipIOCLine(path, lineNo, "indicator contains ':' (not valid in FQDN — use ';' as score separator)")
			} else {
				warnSkipIOCLine(path, lineNo, "invalid domain or IP")
			}
			continue
		}
		domains[host] = c2IOCEntry{indicator: host, score: score}
	}

	if err := scanner.Err(); err != nil {
		if required {
			return nil, nil, err
		}
		log.WithError(err).WithField("path", path).Warn("Error while reading C2 IOC file; using parsed entries")
	}

	return domains, ips, nil
}

func isLikelyDomain(value string) bool {
	if value == "" {
		return false
	}
	if strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	if strings.Contains(value, "..") {
		return false
	}
	if !strings.Contains(value, ".") {
		return false
	}

	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '.' || r == '-':
		default:
			return false
		}
	}

	return true
}
