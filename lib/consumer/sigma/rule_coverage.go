package sigma

import (
	"fmt"
	"strings"

	sigma "github.com/markuskont/go-sigma-rule-engine"
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
	return ""
}

// Excluded returns the rules removed because they can never match.
func (s *SigmaConsumer) Excluded() []ExcludedRule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]ExcludedRule(nil), s.excluded...)
}

func (s *SigmaConsumer) reportCoverage(rs *sigma.Ruleset, excluded []ExcludedRule) {
	for _, ex := range excluded {
		log.WithFields(log.Fields{
			"rule_path": ex.Path, "sigma_rule": ex.ID, "sigma_title": ex.Title, "reason": ex.Reason,
		}).Warn("Sigma rule excluded: it can never match on this host")
	}
	if len(excluded)+rs.Failed+rs.Unsupported > 0 {
		log.WithFields(log.Fields{
			"excluded_never_match": len(excluded),
			"failed":               rs.Failed,
			"unsupported":          rs.Unsupported,
		}).Warn("Some Sigma rules are not active")
	}
}
