package remediation

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeFW struct{ live []int }

func (f *fakeFW) Name() string                           { return "fake" }
func (f *fakeFW) Render(p []int) string                  { return "" }
func (f *fakeFW) Validate(context.Context, []int) error  { return nil }
func (f *fakeFW) Apply(_ context.Context, p []int) error { f.live = p; return nil }
func (f *fakeFW) Remove(context.Context) error           { f.live = nil; return nil }
func (f *fakeFW) List(context.Context) (string, error)   { return "", nil }
func (f *fakeFW) Available(context.Context) error        { return nil }

func TestPlanApplyRollback(t *testing.T) {
	fw := &fakeFW{}
	m := &Manager{FW: fw, StateDir: t.TempDir()}
	ctx := context.Background()

	pl, err := m.Plan([]int{3306, 22, 6379}, []int{22})
	if err != nil {
		t.Fatal(err)
	}
	if len(pl.Desired) != 2 || pl.Desired[0] != 3306 {
		t.Fatalf("protected port leaked into plan: %+v", pl)
	}
	if err := m.Apply(ctx, pl, time.Second, nil, nil); err != nil {
		t.Fatal(err)
	}
	pl2, _ := m.Plan([]int{3306}, nil)
	if len(pl2.Remove) != 1 || pl2.Remove[0] != 6379 {
		t.Fatalf("bad diff: %+v", pl2)
	}
	if err := m.Apply(ctx, pl2, time.Second, nil, nil); err != nil {
		t.Fatal(err)
	}
	st, err := m.Rollback(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.BlockedTCP) != 2 || len(fw.live) != 2 {
		t.Fatalf("rollback did not restore: %+v live=%v", st, fw.live)
	}
}

func TestVerifyFailureReverts(t *testing.T) {
	fw := &fakeFW{}
	m := &Manager{FW: fw, StateDir: t.TempDir()}
	pl, _ := m.Plan([]int{8080}, nil)
	err := m.Apply(context.Background(), pl, time.Second, func(context.Context) error { return errors.New("still open") }, nil)
	if err == nil || len(fw.live) != 0 {
		t.Fatalf("expected revert, err=%v live=%v", err, fw.live)
	}
}

func TestUnconfirmedReverts(t *testing.T) {
	fw := &fakeFW{}
	m := &Manager{FW: fw, StateDir: t.TempDir()}
	pl, _ := m.Plan([]int{8080}, nil)
	err := m.Apply(context.Background(), pl, 10*time.Millisecond, nil, func(ctx context.Context) bool { <-ctx.Done(); return false })
	if err == nil || len(fw.live) != 0 {
		t.Fatalf("expected revert, err=%v live=%v", err, fw.live)
	}
}
