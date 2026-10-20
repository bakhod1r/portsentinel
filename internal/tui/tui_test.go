package tui

import (
	"strings"
	"testing"

	"github.com/bakhod1r/portsentinel/internal/config"
	"github.com/bakhod1r/portsentinel/internal/discovery"
	"github.com/bakhod1r/portsentinel/internal/policy"
)

func TestViewRendersFindings(t *testing.T) {
	m := New(config.Default(), nil)
	m.rep = &discovery.Report{Findings: []discovery.Finding{
		{Target: "127.0.0.1", Port: 6379, Proto: "tcp", Service: "redis", Verdict: policy.Block, Reason: "default deny"},
	}}
	out := m.View()
	for _, want := range []string{"PortSentinel", "6379/tcp", "redis", "block"} {
		if !strings.Contains(out, want) {
			t.Errorf("view missing %q", want)
		}
	}
}
