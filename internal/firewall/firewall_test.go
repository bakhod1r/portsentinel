package firewall

import (
	"context"
	"strings"
	"testing"
)

func TestRenderOnlyTouchesOwnTable(t *testing.T) {
	n := &NFTables{Table: "portsentinel"}
	s := n.Render([]int{3306, 6379})
	if !strings.Contains(s, "elements = { 3306, 6379 }") {
		t.Fatalf("missing elements:\n%s", s)
	}
	if strings.Contains(s, "flush ruleset") {
		t.Fatal("must never flush the ruleset")
	}
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, "table ") || strings.HasPrefix(line, "delete ") {
			if !strings.Contains(line, "inet portsentinel") {
				t.Fatalf("foreign table referenced: %q", line)
			}
		}
	}
}

func TestApplyValidatesFirst(t *testing.T) {
	var calls []string
	n := &NFTables{Table: "portsentinel", Run: func(_ context.Context, _ string, name string, args ...string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return "", nil
	}}
	if err := n.Apply(context.Background(), []int{8080}); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || calls[0] != "nft -c -f -" || calls[1] != "nft -f -" {
		t.Fatalf("unexpected calls: %v", calls)
	}
}
