package sigma

import (
	"fmt"
	"sort"
	"strings"

	sigma "github.com/Nextron-Labs/aurora-linux/third_party/go-sigma-rule-engine"
	log "github.com/sirupsen/logrus"
)

// defaultLogsourceServices is used when Config.LogsourceServices is nil.
var defaultLogsourceServices = []string{"auditd"}

// ServiceProvider is implemented by events that belong to Sigma logsource
// services (e.g. "auditd", "syslog", "sshd"). Rules that name a service are
// only evaluated against events that list it; rules without a service see
// every event.
type ServiceProvider interface {
	Services() []string
}

// ExcludedRule is a rule that loaded but can never match on this host.
type ExcludedRule struct {
	Path, ID, Title, Reason string
}

// excludeReason returns why tree can never match, or "" if it can.
func (s *SigmaConsumer) excludeReason(tree *sigma.Tree) string {
	ls := tree.Rule.Logsource
	if p := strings.ToLower(ls.Product); p != "" && p != "linux" {
		return fmt.Sprintf("logsource product %q is not collected (Aurora is Linux-only)", ls.Product)
	}
	service := strings.ToLower(ls.Service)
	if service != "" && !s.services[service] {
		return fmt.Sprintf("logsource service %q is not collected", ls.Service)
	}
	if s.fieldKnown == nil {
		return ""
	}
	known := func(f string) bool { return s.fieldKnown(service, f) }
	if tree.CanMatch(known) {
		return ""
	}
	var unknown []string
	for _, f := range tree.Fields() {
		if !known(f) {
			unknown = append(unknown, f)
		}
	}
	sort.Strings(unknown)
	return fmt.Sprintf("requires field(s) never emitted by the enabled event sources: %s", strings.Join(unknown, ", "))
}

// Excluded returns the rules removed because they can never match.
func (s *SigmaConsumer) Excluded() []ExcludedRule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]ExcludedRule(nil), s.excluded...)
}

func (s *SigmaConsumer) reportCoverage(rs *sigma.Ruleset, excluded []ExcludedRule) {
	for _, sk := range rs.Skipped {
		log.WithFields(log.Fields{"rule_path": sk.Path, "reason": sk.Reason}).
			Warn("Sigma rule skipped: could not be loaded")
	}
	for _, ex := range excluded {
		log.WithFields(log.Fields{
			"rule_path": ex.Path, "sigma_rule": ex.ID, "sigma_title": ex.Title, "reason": ex.Reason,
		}).Warn("Sigma rule excluded: it can never match on this host")
	}
	if len(excluded)+len(rs.Skipped) > 0 {
		log.WithFields(log.Fields{
			"excluded_never_match": len(excluded),
			"skipped_unloadable":   len(rs.Skipped),
		}).Warn("Some Sigma rules are not active")
	}
}
