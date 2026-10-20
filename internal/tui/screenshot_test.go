package tui

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"github.com/bakhod1r/portsentinel/internal/config"
	"github.com/bakhod1r/portsentinel/internal/discovery"
	"github.com/bakhod1r/portsentinel/internal/firewall"
	"github.com/bakhod1r/portsentinel/internal/remediation"
)

// TestScreenshots dumps ANSI frames of the TUI for docs/screenshots.
// Run with: PS_SCREENSHOT_DIR=out go test ./internal/tui -run Screenshots
func TestScreenshots(t *testing.T) {
	dir := os.Getenv("PS_SCREENSHOT_DIR")
	if dir == "" {
		t.Skip("PS_SCREENSHOT_DIR not set")
	}
	lipgloss.SetColorProfile(termenv.TrueColor)
	ports := []int{443, 3306, 6379, 8080, 9100}
	for _, p := range ports {
		ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(p))
		if err != nil {
			t.Skipf("listen %d: %v", p, err)
		}
		defer ln.Close()
	}
	cfg := config.Default()
	cfg.Mode = config.ModeEnforce
	cfg.Scan.Ports = "1-10000"
	cfg.Policy.ManagementPorts = []int{9100}
	mgr := &remediation.Manager{FW: firewall.NewNFTables(), StateDir: t.TempDir()}

	m := New(cfg, mgr)
	m.width, m.height = 120, 30
	write := func(name string, mm Model) {
		if err := os.WriteFile(filepath.Join(dir, name+".ans"), []byte(mm.View()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("01-start", m)

	scanning := m
	scanning.busy, scanning.progress = "scanning", progressMsg{6400, 10000}
	write("02-scanning", scanning)

	rep, err := discovery.Run(context.Background(), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	m.rep = rep
	m.status = "Scan complete: " + strconv.Itoa(len(rep.Findings)) + " open, " + strconv.Itoa(len(rep.Blocked())) + " unauthorized (" + rep.Duration + ")."
	m.cursor = 2
	write("03-findings", m)

	pl, err := mgr.Plan(rep.Blocked(), m.eng.ProtectedPorts())
	if err != nil {
		t.Fatal(err)
	}
	m.plan, m.tab = pl, tabPlan
	m.status = "Plan: +" + strconv.Itoa(len(pl.Add)) + " / -0. Press a to apply."
	write("04-plan", m)

	ask := m
	ask.askApply = true
	write("05-apply-confirm", ask)

	keep := m
	keep.confirmDue = time.Now().Add(47 * time.Second)
	write("06-keep-or-revert", keep)
}
