package policy

import (
	"testing"
	"time"

	"github.com/bakhod1r/portsentinel/internal/config"
)

func TestEvaluate(t *testing.T) {
	t.Setenv("SSH_CONNECTION", "10.0.0.1 5555 10.0.0.2 2222")
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	e := New(config.Policy{
		SSHPort:       22,
		AllowedTCP:    []int{443},
		AllowedRanges: []config.PortRange{{From: 9000, To: 9010}},
		Exceptions: []config.Exception{
			{Port: 8080, Expires: now.Add(time.Hour), Reason: "demo"},
			{Port: 8081, Expires: now.Add(-time.Hour)},
		},
	}, func() time.Time { return now })

	cases := map[int]Verdict{22: Protected, 2222: Protected, 443: Allow, 9005: Allow, 8080: Allow, 8081: Block, 3306: Block}
	for port, want := range cases {
		if got := e.Evaluate(port, "tcp").Verdict; got != want {
			t.Errorf("port %d: got %s want %s", port, got, want)
		}
	}
}
