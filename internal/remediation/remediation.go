// Package remediation plans, applies and rolls back firewall changes.
package remediation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/bakhod1r/portsentinel/internal/audit"
	"github.com/bakhod1r/portsentinel/internal/firewall"
)

// State is the persisted managed firewall state.
type State struct {
	BlockedTCP []int     `json:"blocked_tcp"`
	Applied    time.Time `json:"applied"`
}

// Plan is the difference between current and desired managed state.
type Plan struct {
	Current []int  `json:"current"`
	Desired []int  `json:"desired"`
	Add     []int  `json:"add"`
	Remove  []int  `json:"remove"`
	Script  string `json:"script"`
}

// Empty reports whether the plan changes nothing.
func (p *Plan) Empty() bool { return len(p.Add) == 0 && len(p.Remove) == 0 }

// Manager coordinates the firewall backend with persisted state.
type Manager struct {
	FW       firewall.Backend
	StateDir string
	Audit    *audit.Log
}

func (m *Manager) path(elem ...string) string {
	return filepath.Join(append([]string{m.StateDir}, elem...)...)
}

// Current loads the last known-good state (empty if none).
func (m *Manager) Current() (State, error) {
	return readState(m.path("current.json"))
}

// Plan computes the change from the current state to desired.
// Protected ports are always removed from desired.
func (m *Manager) Plan(desired, protected []int) (*Plan, error) {
	cur, err := m.Current()
	if err != nil {
		return nil, err
	}
	prot := toSet(protected)
	var want []int
	for _, p := range uniq(desired) {
		if !prot[p] {
			want = append(want, p)
		}
	}
	cs, ws := toSet(cur.BlockedTCP), toSet(want)
	pl := &Plan{Current: uniq(cur.BlockedTCP), Desired: want, Script: m.FW.Render(want)}
	for p := range ws {
		if !cs[p] {
			pl.Add = append(pl.Add, p)
		}
	}
	for p := range cs {
		if !ws[p] {
			pl.Remove = append(pl.Remove, p)
		}
	}
	sort.Ints(pl.Add)
	sort.Ints(pl.Remove)
	return pl, nil
}

// Apply loads the plan. If confirm is non-nil, it is called after apply and
// the change is reverted unless confirm returns true before timeout.
// verify, if non-nil, is called after apply; an error triggers rollback.
func (m *Manager) Apply(ctx context.Context, pl *Plan, timeout time.Duration,
	verify func(context.Context) error, confirm func(context.Context) bool) error {

	if err := os.MkdirAll(m.path("history"), 0o750); err != nil {
		return err
	}
	prev, err := m.Current()
	if err != nil {
		return err
	}
	// Pending marker allows recovery after a crash mid-apply.
	if err := writeState(m.path("pending.json"), prev); err != nil {
		return err
	}
	detail := map[string]any{"add": pl.Add, "remove": pl.Remove, "desired": pl.Desired}
	if err := m.FW.Apply(ctx, pl.Desired); err != nil {
		m.Audit.Record("apply", "failed", detail, err)
		_ = os.Remove(m.path("pending.json"))
		return err
	}
	revert := func(reason error) error {
		rerr := m.FW.Apply(context.Background(), prev.BlockedTCP)
		m.Audit.Record("rollback", status(rerr), map[string]any{"restored": prev.BlockedTCP, "reason": reason.Error()}, rerr)
		_ = os.Remove(m.path("pending.json"))
		return errors.Join(reason, rerr)
	}
	if verify != nil {
		if err := verify(ctx); err != nil {
			return revert(fmt.Errorf("verification failed: %w", err))
		}
	}
	if confirm != nil {
		cctx, cancel := context.WithTimeout(ctx, timeout)
		ok := confirm(cctx)
		cancel()
		if !ok {
			return revert(errors.New("change not confirmed before timeout"))
		}
	}
	next := State{BlockedTCP: pl.Desired, Applied: time.Now().UTC()}
	if prev.BlockedTCP != nil || !prev.Applied.IsZero() {
		_ = writeState(m.path("history", prev.Applied.Format("20060102T150405Z")+".json"), prev)
	}
	if err := writeState(m.path("current.json"), next); err != nil {
		return err
	}
	_ = os.Remove(m.path("pending.json"))
	m.Audit.Record("apply", "ok", detail, nil)
	return nil
}

// Rollback restores the most recent history entry (or removes all rules if none).
func (m *Manager) Rollback(ctx context.Context) (State, error) {
	entries, _ := filepath.Glob(m.path("history", "*.json"))
	sort.Strings(entries)
	var target State
	if len(entries) > 0 {
		var err error
		if target, err = readState(entries[len(entries)-1]); err != nil {
			return target, err
		}
	}
	var err error
	if len(target.BlockedTCP) == 0 {
		err = m.FW.Remove(ctx)
	} else {
		err = m.FW.Apply(ctx, target.BlockedTCP)
	}
	m.Audit.Record("rollback", status(err), map[string]any{"restored": target.BlockedTCP}, err)
	if err != nil {
		return target, err
	}
	if len(entries) > 0 {
		_ = os.Remove(entries[len(entries)-1])
	}
	target.Applied = time.Now().UTC()
	return target, writeState(m.path("current.json"), target)
}

// Recover restores the pre-apply state if a previous run was interrupted.
// It returns true when recovery was performed.
func (m *Manager) Recover(ctx context.Context) (bool, error) {
	pending := m.path("pending.json")
	if _, err := os.Stat(pending); errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	prev, err := readState(pending)
	if err != nil {
		return false, err
	}
	err = m.FW.Apply(ctx, prev.BlockedTCP)
	m.Audit.Record("recover", status(err), map[string]any{"restored": prev.BlockedTCP}, err)
	if err == nil {
		_ = os.Remove(pending)
	}
	return true, err
}

func status(err error) string {
	if err != nil {
		return "failed"
	}
	return "ok"
}

func readState(path string) (State, error) {
	var s State
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	return s, json.Unmarshal(b, &s)
}

func writeState(path string, s State) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func toSet(xs []int) map[int]bool {
	m := make(map[int]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

func uniq(xs []int) []int {
	out := make([]int, 0, len(xs))
	for p := range toSet(xs) {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}
