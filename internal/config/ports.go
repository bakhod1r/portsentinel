package config

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ParsePorts expands a spec like "22,80,1000-1010" into a sorted unique list.
func ParsePorts(spec string) ([]int, error) {
	seen := map[int]struct{}{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi := part, part
		if i := strings.IndexByte(part, '-'); i >= 0 {
			lo, hi = part[:i], part[i+1:]
		}
		a, err1 := strconv.Atoi(lo)
		b, err2 := strconv.Atoi(hi)
		if err1 != nil || err2 != nil || a < 1 || b > 65535 || a > b {
			return nil, fmt.Errorf("invalid port spec %q", part)
		}
		for p := a; p <= b; p++ {
			seen[p] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil, fmt.Errorf("empty port spec")
	}
	out := make([]int, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Ints(out)
	return out, nil
}
