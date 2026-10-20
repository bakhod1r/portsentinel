// Package tui provides an interactive terminal dashboard.
package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/bakhod1r/portsentinel/internal/config"
	"github.com/bakhod1r/portsentinel/internal/discovery"
	"github.com/bakhod1r/portsentinel/internal/policy"
	"github.com/bakhod1r/portsentinel/internal/remediation"
)

var (
	titleStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FAFAFA")).Background(lipgloss.Color("#7D56F4")).Padding(0, 1)
	tabActive   = lipgloss.NewStyle().Bold(true).Underline(true).Foreground(lipgloss.Color("#7D56F4")).Padding(0, 1)
	tabInactive = lipgloss.NewStyle().Foreground(lipgloss.Color("244")).Padding(0, 1)
	headerStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("252"))
	selStyle    = lipgloss.NewStyle().Background(lipgloss.Color("237"))
	allowStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	protStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("39"))
	blockStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	helpStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	statusStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("229"))
	warnStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Bold(true)
	panelStyle  = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("62")).Padding(0, 1)
)

type tab int

const (
	tabFindings tab = iota
	tabPlan
	tabRules
)

type (
	progressMsg struct{ done, total int }
	scanDoneMsg struct {
		rep *discovery.Report
		err error
	}
	planMsg struct {
		plan *remediation.Plan
		err  error
	}
	applyDoneMsg struct{ err error }
	rulesMsg     struct {
		text string
		err  error
	}
	confirmReqMsg struct{ deadline time.Time }
	tickMsg       time.Time
)

// Model is the Bubble Tea model.
type Model struct {
	cfg *config.Config
	mgr *remediation.Manager
	eng *policy.Engine

	tab      tab
	rep      *discovery.Report
	plan     *remediation.Plan
	rules    string
	cursor   int
	busy     string
	status   string
	progress progressMsg
	width    int
	height   int

	askApply   bool
	confirmCh  chan bool
	confirmDue time.Time
	progCh     chan progressMsg
}

// New creates the TUI model.
func New(cfg *config.Config, mgr *remediation.Manager) Model {
	return Model{cfg: cfg, mgr: mgr, eng: policy.New(cfg.Policy, nil), status: "Press s to scan."}
}

// Run starts the TUI.
func Run(cfg *config.Config, mgr *remediation.Manager) error {
	program = tea.NewProgram(New(cfg, mgr), tea.WithAltScreen())
	_, err := program.Run()
	return err
}

func (m Model) Init() tea.Cmd { return nil }

func (m Model) scanCmd() tea.Cmd {
	ch := m.progCh
	cfg := m.cfg
	return func() tea.Msg {
		rep, err := discovery.Run(context.Background(), cfg, func(d, t int) {
			if d%32 == 0 || d == t {
				select {
				case ch <- progressMsg{d, t}:
				default:
				}
			}
		})
		return scanDoneMsg{rep, err}
	}
}

func waitProgress(ch chan progressMsg) tea.Cmd {
	return func() tea.Msg {
		p, ok := <-ch
		if !ok {
			return nil
		}
		return p
	}
}

func (m Model) planCmd() tea.Cmd {
	return func() tea.Msg {
		if m.rep == nil {
			return planMsg{err: fmt.Errorf("run a scan first")}
		}
		p, err := m.mgr.Plan(m.rep.Blocked(), m.eng.ProtectedPorts())
		return planMsg{p, err}
	}
}

func (m Model) rulesCmd() tea.Cmd {
	return func() tea.Msg {
		t, err := m.mgr.FW.List(context.Background())
		return rulesMsg{t, err}
	}
}

func (m Model) applyCmd(send func(tea.Msg)) tea.Cmd {
	plan, mgr, timeout, ch := m.plan, m.mgr, m.cfg.RollbackTimeout, m.confirmCh
	return func() tea.Msg {
		err := mgr.Apply(context.Background(), plan, timeout, nil, func(ctx context.Context) bool {
			dl, _ := ctx.Deadline()
			send(confirmReqMsg{dl})
			select {
			case ok := <-ch:
				return ok
			case <-ctx.Done():
				return false
			}
		})
		return applyDoneMsg{err}
	}
}

func tick() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// program lets background commands push messages (e.g. confirm prompts).
var program *tea.Program

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
	case progressMsg:
		m.progress = msg
		return m, waitProgress(m.progCh)
	case scanDoneMsg:
		m.busy = ""
		if msg.err != nil {
			m.status = "scan failed: " + msg.err.Error()
			return m, nil
		}
		m.rep, m.cursor, m.plan = msg.rep, 0, nil
		m.status = fmt.Sprintf("Scan complete: %d open, %d unauthorized (%s).", len(msg.rep.Findings), len(msg.rep.Blocked()), msg.rep.Duration)
	case planMsg:
		m.busy = ""
		if msg.err != nil {
			m.status = "plan: " + msg.err.Error()
			return m, nil
		}
		m.plan, m.tab = msg.plan, tabPlan
		if msg.plan.Empty() {
			m.status = "Plan: no changes."
		} else {
			m.status = fmt.Sprintf("Plan: +%d / -%d. Press a to apply.", len(msg.plan.Add), len(msg.plan.Remove))
		}
	case rulesMsg:
		m.busy = ""
		if msg.err != nil {
			m.rules = "error: " + msg.err.Error()
		} else {
			m.rules = msg.text
		}
	case confirmReqMsg:
		m.confirmDue = msg.deadline
		m.status = "Applied. Press y to keep the change, n to revert."
		return m, tick()
	case tickMsg:
		if !m.confirmDue.IsZero() {
			return m, tick()
		}
	case applyDoneMsg:
		m.busy, m.confirmDue = "", time.Time{}
		if msg.err != nil {
			m.status = "apply: " + msg.err.Error()
		} else {
			m.status = "Firewall updated and confirmed."
			m.plan = nil
		}
	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m Model) handleKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := k.String()
	if !m.confirmDue.IsZero() {
		switch key {
		case "y":
			m.confirmCh <- true
		case "n":
			m.confirmCh <- false
		}
		return m, nil
	}
	if m.askApply {
		m.askApply = false
		if key == "y" {
			m.busy = "applying"
			m.confirmCh = make(chan bool, 1)
			return m, m.applyCmd(program.Send)
		}
		m.status = "Apply cancelled."
		return m, nil
	}
	switch key {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "tab", "right", "l":
		m.tab = (m.tab + 1) % 3
		if m.tab == tabRules {
			return m, m.rulesCmd()
		}
	case "shift+tab", "left", "h":
		m.tab = (m.tab + 2) % 3
		if m.tab == tabRules {
			return m, m.rulesCmd()
		}
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.rep != nil && m.cursor < len(m.rep.Findings)-1 {
			m.cursor++
		}
	case "s":
		if m.busy == "" {
			m.busy, m.progress, m.tab = "scanning", progressMsg{}, tabFindings
			m.progCh = make(chan progressMsg, 8)
			return m, tea.Batch(m.scanCmd(), waitProgress(m.progCh))
		}
	case "p":
		if m.busy == "" {
			return m, m.planCmd()
		}
	case "a":
		switch {
		case m.plan == nil || m.plan.Empty():
			m.status = "Nothing to apply. Press p to build a plan."
		case m.cfg.Mode != config.ModeEnforce:
			m.status = fmt.Sprintf("Mode is %q: enforcement disabled (set mode: enforce).", m.cfg.Mode)
		default:
			m.askApply = true
		}
	}
	return m, nil
}

func (m Model) View() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("PortSentinel") + "  " +
		helpStyle.Render(fmt.Sprintf("mode=%s backend=%s targets=%s", m.cfg.Mode, m.cfg.Backend, strings.Join(m.cfg.Targets, ","))) + "\n\n")
	for i, name := range []string{"Findings", "Plan", "Rules"} {
		if tab(i) == m.tab {
			b.WriteString(tabActive.Render(name))
		} else {
			b.WriteString(tabInactive.Render(name))
		}
	}
	b.WriteString("\n\n")

	switch m.tab {
	case tabFindings:
		b.WriteString(m.viewFindings())
	case tabPlan:
		b.WriteString(m.viewPlan())
	case tabRules:
		body := m.rules
		if body == "" {
			body = "(no managed rules loaded)"
		}
		b.WriteString(panelStyle.Render(strings.TrimRight(body, "\n")))
	}
	b.WriteString("\n\n")

	switch {
	case m.busy == "scanning":
		b.WriteString(statusStyle.Render(fmt.Sprintf("Scanning… %s", bar(m.progress.done, m.progress.total, 30))))
	case !m.confirmDue.IsZero():
		left := time.Until(m.confirmDue).Round(time.Second)
		b.WriteString(warnStyle.Render(fmt.Sprintf("Keep firewall change? [y/n] — auto-revert in %s", left)))
	case m.askApply:
		b.WriteString(warnStyle.Render(fmt.Sprintf("Apply plan (+%d / -%d) to the live firewall? [y/N]", len(m.plan.Add), len(m.plan.Remove))))
	default:
		b.WriteString(statusStyle.Render(m.status))
	}
	b.WriteString("\n" + helpStyle.Render("s scan • p plan • a apply • tab switch • j/k move • q quit"))
	return b.String()
}

func (m Model) viewFindings() string {
	if m.rep == nil {
		return helpStyle.Render("No scan results yet.")
	}
	if len(m.rep.Findings) == 0 {
		return allowStyle.Render("No open ports found on " + strings.Join(m.rep.Addresses, ", "))
	}
	var b strings.Builder
	row := "%-3s %-24s %-9s %-14s %-18s %-10s %s"
	b.WriteString(headerStyle.Render(fmt.Sprintf(row, "", "TARGET", "PORT", "SERVICE", "PROCESS", "VERDICT", "REASON")) + "\n")
	for i, f := range m.rep.Findings {
		var vs lipgloss.Style
		icon := "●"
		switch f.Verdict {
		case policy.Allow:
			vs = allowStyle
		case policy.Protected:
			vs, icon = protStyle, "◆"
		default:
			vs, icon = blockStyle, "✖"
		}
		proc := f.Process
		if f.PID > 0 {
			proc = fmt.Sprintf("%s[%d]", f.Process, f.PID)
		}
		line := fmt.Sprintf(row, vs.Render(icon), f.Target, fmt.Sprintf("%d/%s", f.Port, f.Proto),
			orDash(f.Service), orDash(proc), vs.Render(fmt.Sprintf("%-10s", f.Verdict)), f.Reason)
		if i == m.cursor {
			line = selStyle.Render(line)
		}
		b.WriteString(line + "\n")
	}
	if f := m.rep.Findings[m.cursor]; f.Banner != "" {
		b.WriteString("\n" + helpStyle.Render("banner: ") + f.Banner)
	}
	return b.String()
}

func (m Model) viewPlan() string {
	if m.plan == nil {
		return helpStyle.Render("No plan. Press p after a scan.")
	}
	if m.plan.Empty() {
		return allowStyle.Render("No changes: managed firewall state already matches policy.")
	}
	var b strings.Builder
	for _, p := range m.plan.Add {
		b.WriteString(blockStyle.Render(fmt.Sprintf("+ block tcp/%d", p)) + "\n")
	}
	for _, p := range m.plan.Remove {
		b.WriteString(allowStyle.Render(fmt.Sprintf("- unblock tcp/%d", p)) + "\n")
	}
	b.WriteString("\n" + panelStyle.Render(strings.TrimRight(m.plan.Script, "\n")))
	return b.String()
}

func bar(done, total, width int) string {
	if total == 0 {
		return "[" + strings.Repeat("░", width) + "]"
	}
	n := done * width / total
	return fmt.Sprintf("[%s%s] %d/%d", strings.Repeat("█", n), strings.Repeat("░", width-n), done, total)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
