// Package firewall manages PortSentinel-owned firewall rules.
package firewall

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"sort"
	"strings"
)

// Backend is a firewall implementation that only manipulates rules it owns.
type Backend interface {
	Name() string
	// Render returns the exact ruleset that Apply would load.
	Render(blockedTCP []int) string
	// Validate checks a ruleset without applying it.
	Validate(ctx context.Context, blockedTCP []int) error
	// Apply atomically replaces the managed ruleset.
	Apply(ctx context.Context, blockedTCP []int) error
	// Remove deletes all managed rules.
	Remove(ctx context.Context) error
	// List returns the live managed ruleset as text.
	List(ctx context.Context) (string, error)
	// Available reports whether the backend binary is usable.
	Available(ctx context.Context) error
}

// Runner executes a command with optional stdin; replaceable in tests.
type Runner func(ctx context.Context, stdin string, name string, args ...string) (string, error)

// ExecRunner runs real commands.
func ExecRunner(ctx context.Context, stdin, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

// NFTables manages a dedicated "inet portsentinel" table. It never touches
// other tables and never flushes the global ruleset.
type NFTables struct {
	Table string
	Run   Runner
}

// NewNFTables returns an adapter using the real nft binary.
func NewNFTables() *NFTables { return &NFTables{Table: "portsentinel", Run: ExecRunner} }

func (n *NFTables) Name() string { return "nftables" }

// Render produces an atomic script: create-if-missing, delete, recreate.
// Only the managed table is affected.
func (n *NFTables) Render(blocked []int) string {
	ports := append([]int(nil), blocked...)
	sort.Ints(ports)
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {}\n", n.Table)
	fmt.Fprintf(&b, "delete table inet %s\n", n.Table)
	fmt.Fprintf(&b, "table inet %s {\n", n.Table)
	b.WriteString("\tcomment \"managed by portsentinel; do not edit\"\n")
	b.WriteString("\tset blocked_tcp {\n\t\ttype inet_service\n")
	if len(ports) > 0 {
		elems := make([]string, len(ports))
		for i, p := range ports {
			elems[i] = fmt.Sprint(p)
		}
		fmt.Fprintf(&b, "\t\telements = { %s }\n", strings.Join(elems, ", "))
	}
	b.WriteString("\t}\n")
	b.WriteString("\tchain input {\n\t\ttype filter hook input priority -10; policy accept;\n")
	b.WriteString("\t\tiifname \"lo\" accept\n")
	b.WriteString("\t\tct state established,related accept\n")
	b.WriteString("\t\ttcp dport @blocked_tcp counter drop comment \"portsentinel-block\"\n")
	b.WriteString("\t}\n}\n")
	return b.String()
}

func (n *NFTables) Validate(ctx context.Context, blocked []int) error {
	_, err := n.Run(ctx, n.Render(blocked), "nft", "-c", "-f", "-")
	return err
}

func (n *NFTables) Apply(ctx context.Context, blocked []int) error {
	if err := n.Validate(ctx, blocked); err != nil {
		return fmt.Errorf("validation failed, nothing applied: %w", err)
	}
	_, err := n.Run(ctx, n.Render(blocked), "nft", "-f", "-")
	return err
}

func (n *NFTables) Remove(ctx context.Context) error {
	script := fmt.Sprintf("table inet %s {}\ndelete table inet %s\n", n.Table, n.Table)
	_, err := n.Run(ctx, script, "nft", "-f", "-")
	return err
}

func (n *NFTables) List(ctx context.Context) (string, error) {
	return n.Run(ctx, "", "nft", "list", "table", "inet", n.Table)
}

func (n *NFTables) Available(ctx context.Context) error {
	_, err := n.Run(ctx, "", "nft", "--version")
	return err
}
