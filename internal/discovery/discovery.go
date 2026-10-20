// Package discovery runs the probe → inventory → policy pipeline.
package discovery

import (
	"context"
	"sort"
	"time"

	"github.com/bakhod1r/portsentinel/internal/config"
	"github.com/bakhod1r/portsentinel/internal/inventory"
	"github.com/bakhod1r/portsentinel/internal/policy"
	"github.com/bakhod1r/portsentinel/internal/probe"
)

// Finding is an exposed port correlated with local data and a policy decision.
type Finding struct {
	Target   string         `json:"target"`
	Port     int            `json:"port"`
	Proto    string         `json:"proto"`
	Service  string         `json:"service,omitempty"`
	Banner   string         `json:"banner,omitempty"`
	Process  string         `json:"process,omitempty"`
	PID      int            `json:"pid,omitempty"`
	Verdict  policy.Verdict `json:"verdict"`
	Reason   string         `json:"reason"`
	Detected time.Time      `json:"detected"`
}

// Report is the result of one discovery run.
type Report struct {
	Started   time.Time `json:"started"`
	Duration  string    `json:"duration"`
	Addresses []string  `json:"addresses"`
	Findings  []Finding `json:"findings"`
	Errors    []string  `json:"errors,omitempty"`
}

// Blocked returns the unique ports with a Block verdict.
func (r *Report) Blocked() []int {
	set := map[int]bool{}
	for _, f := range r.Findings {
		if f.Verdict == policy.Block {
			set[f.Port] = true
		}
	}
	out := make([]int, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// Run performs a scan of the configured targets.
func Run(ctx context.Context, cfg *config.Config, progress func(done, total int)) (*Report, error) {
	rep := &Report{Started: time.Now().UTC()}
	addrs, err := probe.ResolveTargets(ctx, cfg.Targets)
	if err != nil {
		return nil, err
	}
	rep.Addresses = addrs
	ports, err := config.ParsePorts(cfg.Scan.Ports)
	if err != nil {
		return nil, err
	}
	results := probe.ScanTCP(ctx, addrs, ports, probe.Options{
		Timeout: cfg.Scan.Timeout, Concurrency: cfg.Scan.Concurrency, Banner: cfg.Scan.Banner,
	}, progress)

	byPort := map[int]inventory.Socket{}
	if socks, err := inventory.Listening("/proc"); err != nil {
		rep.Errors = append(rep.Errors, "inventory: "+err.Error())
	} else {
		for _, s := range socks {
			if _, ok := byPort[s.Port]; !ok || s.Process != "" {
				byPort[s.Port] = s
			}
		}
	}

	eng := policy.New(cfg.Policy, nil)
	for _, r := range results {
		d := eng.Evaluate(r.Port, r.Proto)
		f := Finding{
			Target: r.Target, Port: r.Port, Proto: r.Proto, Service: r.Service, Banner: r.Banner,
			Verdict: d.Verdict, Reason: d.Reason, Detected: time.Now().UTC(),
		}
		if s, ok := byPort[r.Port]; ok {
			f.Process, f.PID = s.Process, s.PID
		}
		rep.Findings = append(rep.Findings, f)
	}
	sort.Slice(rep.Findings, func(i, j int) bool {
		a, b := rep.Findings[i], rep.Findings[j]
		if a.Target != b.Target {
			return a.Target < b.Target
		}
		return a.Port < b.Port
	})
	rep.Duration = time.Since(rep.Started).Round(time.Millisecond).String()
	return rep, nil
}
