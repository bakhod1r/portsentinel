// Package report renders discovery results for terminals and machines.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/bakhod1r/portsentinel/internal/discovery"
	"github.com/bakhod1r/portsentinel/internal/remediation"
)

// JSON writes v as indented JSON.
func JSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// Table writes a human-readable findings table.
func Table(w io.Writer, r *discovery.Report) {
	fmt.Fprintf(w, "Targets: %v   Duration: %s\n\n", r.Addresses, r.Duration)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "TARGET\tPORT\tSERVICE\tPROCESS\tVERDICT\tREASON")
	for _, f := range r.Findings {
		proc := f.Process
		if f.PID > 0 {
			proc = fmt.Sprintf("%s[%d]", f.Process, f.PID)
		}
		fmt.Fprintf(tw, "%s\t%d/%s\t%s\t%s\t%s\t%s\n", f.Target, f.Port, f.Proto, dash(f.Service), dash(proc), f.Verdict, f.Reason)
	}
	tw.Flush()
	if len(r.Findings) == 0 {
		fmt.Fprintln(w, "No open ports found.")
	}
	for _, e := range r.Errors {
		fmt.Fprintln(w, "warning:", e)
	}
}

// PlanText writes a plan summary and the ruleset that would be loaded.
func PlanText(w io.Writer, p *remediation.Plan) {
	if p.Empty() {
		fmt.Fprintln(w, "No changes. Managed firewall state matches policy.")
		return
	}
	for _, port := range p.Add {
		fmt.Fprintf(w, "  + block tcp/%d\n", port)
	}
	for _, port := range p.Remove {
		fmt.Fprintf(w, "  - unblock tcp/%d\n", port)
	}
	fmt.Fprintf(w, "\nRuleset to load:\n%s", p.Script)
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
