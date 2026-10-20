// Package policy decides whether an exposed port is permitted.
package policy

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/bakhod1r/portsentinel/internal/config"
)

// Verdict is the outcome of evaluating one port.
type Verdict string

const (
	Allow     Verdict = "allow"
	Protected Verdict = "protected"
	Block     Verdict = "block"
)

// Decision explains a verdict.
type Decision struct {
	Port    int     `json:"port"`
	Proto   string  `json:"proto"`
	Verdict Verdict `json:"verdict"`
	Reason  string  `json:"reason"`
}

// Engine evaluates ports against a policy.
type Engine struct {
	p   config.Policy
	now func() time.Time
}

// New builds an engine. now may be nil.
func New(p config.Policy, now func() time.Time) *Engine {
	if now == nil {
		now = time.Now
	}
	return &Engine{p: p, now: now}
}

// ProtectedPorts returns ports that must never be blocked: SSH, management
// ports and the local port of the current SSH session.
func (e *Engine) ProtectedPorts() []int {
	set := map[int]bool{e.p.SSHPort: true}
	for _, p := range e.p.ManagementPorts {
		set[p] = true
	}
	if p := activeSSHPort(); p > 0 {
		set[p] = true
	}
	out := make([]int, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	return out
}

// Evaluate returns the decision for a TCP port.
func (e *Engine) Evaluate(port int, proto string) Decision {
	d := Decision{Port: port, Proto: proto}
	for _, p := range e.ProtectedPorts() {
		if p == port {
			d.Verdict, d.Reason = Protected, "management/SSH access"
			return d
		}
	}
	for _, p := range e.p.AllowedTCP {
		if p == port {
			d.Verdict, d.Reason = Allow, "explicit allowlist"
			return d
		}
	}
	for _, r := range e.p.AllowedRanges {
		if port >= r.From && port <= r.To {
			d.Verdict, d.Reason = Allow, fmt.Sprintf("allowed range %d-%d", r.From, r.To)
			return d
		}
	}
	for _, ex := range e.p.Exceptions {
		if ex.Port == port && (ex.Proto == "" || ex.Proto == proto) && e.now().Before(ex.Expires) {
			d.Verdict, d.Reason = Allow, "exception until "+ex.Expires.Format(time.RFC3339)+": "+ex.Reason
			return d
		}
	}
	d.Verdict, d.Reason = Block, "not in policy (default deny)"
	return d
}

// activeSSHPort reads the server port from SSH_CONNECTION ("cip cport sip sport").
func activeSSHPort() int {
	f := strings.Fields(os.Getenv("SSH_CONNECTION"))
	if len(f) != 4 {
		return 0
	}
	p, _ := strconv.Atoi(f[3])
	return p
}
