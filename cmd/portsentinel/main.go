// Command portsentinel detects externally exposed ports and enforces a firewall policy.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/bakhod1r/portsentinel/internal/audit"
	"github.com/bakhod1r/portsentinel/internal/config"
	"github.com/bakhod1r/portsentinel/internal/discovery"
	"github.com/bakhod1r/portsentinel/internal/firewall"
	"github.com/bakhod1r/portsentinel/internal/policy"
	"github.com/bakhod1r/portsentinel/internal/probe"
	"github.com/bakhod1r/portsentinel/internal/remediation"
	"github.com/bakhod1r/portsentinel/internal/report"
	"github.com/bakhod1r/portsentinel/internal/tui"
)

const usage = `PortSentinel — external port exposure detection & firewall enforcement

Usage: portsentinel <command> [flags]

Commands:
  init       create an initial configuration
  scan       perform an exposure scan
  audit      compare observed exposure with policy (exit 2 on violations)
  plan       display proposed firewall changes
  apply      apply approved remediation (requires mode: enforce)
  verify     verify blocked ports are unreachable
  rules      list managed firewall rules
  rollback   restore the previous managed state
  status     show managed state
  monitor    run scans periodically
  doctor     diagnose permissions, backend and connectivity
  tui        interactive dashboard

Global flags:
  -c, --config PATH   configuration file (default /etc/portsentinel/config.yaml)
`

func main() {
	if len(os.Args) < 2 || os.Args[1] == "-h" || os.Args[1] == "--help" || os.Args[1] == "help" {
		fmt.Print(usage)
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1], os.Args[2:]); err != nil {
		var ex exitErr
		if errors.As(err, &ex) {
			os.Exit(int(ex))
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

type exitErr int

func (e exitErr) Error() string { return fmt.Sprintf("exit %d", int(e)) }

type app struct {
	cfg *config.Config
	mgr *remediation.Manager
	log *audit.Log
}

func run(ctx context.Context, cmd string, args []string) error {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	cfgPath := fs.String("config", "/etc/portsentinel/config.yaml", "config file")
	fs.StringVar(cfgPath, "c", "/etc/portsentinel/config.yaml", "config file (shorthand)")
	asJSON := fs.Bool("json", false, "JSON output")
	yes := fs.Bool("yes", false, "skip interactive confirmation (apply)")
	force := fs.Bool("force", false, "overwrite existing config (init)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if cmd == "init" {
		if _, err := os.Stat(*cfgPath); err == nil && !*force {
			return fmt.Errorf("%s exists (use --force)", *cfgPath)
		}
		if err := os.MkdirAll(dir(*cfgPath), 0o750); err != nil {
			return err
		}
		if err := config.Default().Save(*cfgPath); err != nil {
			return err
		}
		fmt.Println("wrote", *cfgPath, "(mode: audit). Review targets and policy before enabling enforce.")
		return nil
	}

	a, err := load(*cfgPath)
	if err != nil {
		return err
	}
	if recovered, err := a.mgr.Recover(ctx); recovered {
		fmt.Fprintln(os.Stderr, "recovered from interrupted apply; previous state restored")
		if err != nil {
			return fmt.Errorf("recovery: %w", err)
		}
	}

	switch cmd {
	case "scan", "audit":
		rep, err := a.scan(ctx)
		if err != nil {
			return err
		}
		if *asJSON {
			_ = report.JSON(os.Stdout, rep)
		} else {
			report.Table(os.Stdout, rep)
		}
		if cmd == "audit" && len(rep.Blocked()) > 0 {
			return exitErr(2)
		}
	case "plan", "apply":
		rep, err := a.scan(ctx)
		if err != nil {
			return err
		}
		pl, err := a.mgr.Plan(rep.Blocked(), policy.New(a.cfg.Policy, nil).ProtectedPorts())
		if err != nil {
			return err
		}
		if *asJSON {
			_ = report.JSON(os.Stdout, pl)
		} else {
			report.PlanText(os.Stdout, pl)
		}
		if cmd == "plan" || pl.Empty() {
			return nil
		}
		return a.apply(ctx, pl, *yes)
	case "verify":
		return a.verify(ctx)
	case "rules":
		out, err := a.mgr.FW.List(ctx)
		if err != nil {
			return err
		}
		fmt.Print(out)
	case "status":
		st, err := a.mgr.Current()
		if err != nil {
			return err
		}
		return report.JSON(os.Stdout, map[string]any{"mode": a.cfg.Mode, "backend": a.cfg.Backend, "targets": a.cfg.Targets, "managed": st})
	case "rollback":
		st, err := a.mgr.Rollback(ctx)
		if err != nil {
			return err
		}
		fmt.Printf("restored managed state: blocked tcp %v\n", st.BlockedTCP)
	case "monitor":
		return a.monitor(ctx)
	case "doctor":
		a.doctor(ctx)
	case "tui":
		return tui.Run(a.cfg, a.mgr)
	default:
		fmt.Print(usage)
		return fmt.Errorf("unknown command %q", cmd)
	}
	return nil
}

func load(path string) (*app, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	log, err := audit.Open(cfg.AuditLog)
	if err != nil {
		fmt.Fprintln(os.Stderr, "warning: audit log disabled:", err)
		log = nil
	}
	return &app{
		cfg: cfg,
		log: log,
		mgr: &remediation.Manager{FW: firewall.NewNFTables(), StateDir: cfg.StateDir, Audit: log},
	}, nil
}

func (a *app) scan(ctx context.Context) (*discovery.Report, error) {
	rep, err := discovery.Run(ctx, a.cfg, nil)
	if err != nil {
		a.log.Record("scan", "failed", nil, err)
		return nil, err
	}
	a.log.Record("scan", "ok", map[string]any{"open": len(rep.Findings), "unauthorized": rep.Blocked()}, nil)
	return rep, nil
}

func (a *app) apply(ctx context.Context, pl *remediation.Plan, yes bool) error {
	if a.cfg.Mode != config.ModeEnforce {
		fmt.Printf("\nmode is %q: no changes applied (set mode: enforce to allow).\n", a.cfg.Mode)
		return nil
	}
	if os.Geteuid() != 0 {
		return errors.New("apply requires root")
	}
	if !yes && !ask("\nApply these changes?") {
		return errors.New("aborted")
	}
	var confirm func(context.Context) bool
	if !yes {
		confirm = func(ctx context.Context) bool {
			fmt.Printf("Applied. Type 'yes' within %s to keep the change, otherwise it is reverted: ", a.cfg.RollbackTimeout)
			ch := make(chan bool, 1)
			go func() { ch <- ask("") }()
			select {
			case ok := <-ch:
				return ok
			case <-ctx.Done():
				fmt.Println("\ntimeout")
				return false
			}
		}
	}
	verify := func(ctx context.Context) error { return a.verifyPorts(ctx, pl.Desired) }
	if err := a.mgr.Apply(ctx, pl, a.cfg.RollbackTimeout, verify, confirm); err != nil {
		return err
	}
	fmt.Println("firewall updated")
	return nil
}

func (a *app) verify(ctx context.Context) error {
	st, err := a.mgr.Current()
	if err != nil {
		return err
	}
	if err := a.verifyPorts(ctx, st.BlockedTCP); err != nil {
		a.log.Record("verify", "failed", nil, err)
		return err
	}
	a.log.Record("verify", "ok", map[string]any{"ports": st.BlockedTCP}, nil)
	fmt.Println("verified: all managed blocked ports are unreachable")
	return nil
}

// verifyPorts checks that blocked ports are not reachable. Run from a separate
// host for true external verification; local probes on loopback bypass the drop rule.
func (a *app) verifyPorts(ctx context.Context, ports []int) error {
	if len(ports) == 0 {
		return nil
	}
	addrs, err := probe.ResolveTargets(ctx, a.cfg.Targets)
	if err != nil {
		return err
	}
	open := probe.ScanTCP(ctx, addrs, ports, probe.Options{Timeout: a.cfg.Scan.Timeout, Concurrency: a.cfg.Scan.Concurrency}, nil)
	if len(open) > 0 {
		var s []string
		for _, r := range open {
			s = append(s, fmt.Sprintf("%s:%d", r.Target, r.Port))
		}
		return fmt.Errorf("still reachable: %s", strings.Join(s, ", "))
	}
	return nil
}

func (a *app) monitor(ctx context.Context) error {
	t := time.NewTicker(a.cfg.Scan.Interval)
	defer t.Stop()
	var last []int
	for {
		rep, err := a.scan(ctx)
		if err != nil {
			fmt.Fprintln(os.Stderr, "scan:", err)
		} else if cur := rep.Blocked(); fmt.Sprint(cur) != fmt.Sprint(last) {
			fmt.Printf("%s exposure changed: unauthorized %v\n", time.Now().Format(time.RFC3339), cur)
			a.log.Record("drift", "detected", map[string]any{"unauthorized": cur, "previous": last}, nil)
			last = cur
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

func (a *app) doctor(ctx context.Context) {
	check := func(name string, err error) {
		if err != nil {
			fmt.Printf("  ✖ %-22s %v\n", name, err)
		} else {
			fmt.Printf("  ✔ %s\n", name)
		}
	}
	fmt.Println("PortSentinel doctor")
	check("config valid", a.cfg.Validate())
	var rootErr error
	if os.Geteuid() != 0 {
		rootErr = errors.New("not root: apply/rules unavailable")
	}
	check("root privileges", rootErr)
	check("nft binary", a.mgr.FW.Available(ctx))
	_, err := os.Stat("/proc/net/tcp")
	check("/proc/net/tcp readable", err)
	check("state dir writable", os.MkdirAll(a.cfg.StateDir, 0o750))
	_, err = probe.ResolveTargets(ctx, a.cfg.Targets)
	check("targets resolvable", err)
}

func ask(prompt string) bool {
	if prompt != "" {
		fmt.Print(prompt + " [y/N]: ")
	}
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	line = strings.ToLower(strings.TrimSpace(line))
	return line == "y" || line == "yes"
}

func dir(p string) string {
	if i := strings.LastIndexByte(p, '/'); i > 0 {
		return p[:i]
	}
	return "."
}
