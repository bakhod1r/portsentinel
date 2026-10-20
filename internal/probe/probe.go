// Package probe implements TCP reachability checks without Nmap.
package probe

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

// State of a probed port.
type State string

const (
	Open     State = "open"
	Closed   State = "closed"
	Filtered State = "filtered"
)

// Result of a single probe.
type Result struct {
	Target  string        `json:"target"`
	Port    int           `json:"port"`
	Proto   string        `json:"proto"`
	State   State         `json:"state"`
	Banner  string        `json:"banner,omitempty"`
	Service string        `json:"service,omitempty"`
	Latency time.Duration `json:"latency_ns"`
}

// Options configures a scan.
type Options struct {
	Timeout     time.Duration
	Concurrency int
	Banner      bool
}

// ResolveTargets expands hostnames into IP addresses (IPv4 and IPv6).
func ResolveTargets(ctx context.Context, targets []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, t := range targets {
		if ip := net.ParseIP(t); ip != nil {
			if !seen[ip.String()] {
				seen[ip.String()] = true
				out = append(out, ip.String())
			}
			continue
		}
		addrs, err := net.DefaultResolver.LookupHost(ctx, t)
		if err != nil {
			return nil, err
		}
		for _, a := range addrs {
			if !seen[a] {
				seen[a] = true
				out = append(out, a)
			}
		}
	}
	return out, nil
}

// ScanTCP probes every (target, port) pair and returns only open ports.
// progress, if non-nil, receives the number of completed probes.
func ScanTCP(ctx context.Context, targets []string, ports []int, opt Options, progress func(done, total int)) []Result {
	type job struct {
		host string
		port int
	}
	jobs := make(chan job)
	var (
		mu      sync.Mutex
		results []Result
		done    int
		wg      sync.WaitGroup
	)
	total := len(targets) * len(ports)
	if opt.Concurrency <= 0 {
		opt.Concurrency = 64
	}
	for i := 0; i < opt.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				r := ProbeTCP(ctx, j.host, j.port, opt)
				mu.Lock()
				if r.State == Open {
					results = append(results, r)
				}
				done++
				if progress != nil {
					progress(done, total)
				}
				mu.Unlock()
			}
		}()
	}
feed:
	for _, h := range targets {
		for _, p := range ports {
			select {
			case jobs <- job{h, p}:
			case <-ctx.Done():
				break feed
			}
		}
	}
	close(jobs)
	wg.Wait()
	return results
}

// ProbeTCP performs a single TCP connect probe.
func ProbeTCP(ctx context.Context, host string, port int, opt Options) Result {
	r := Result{Target: host, Port: port, Proto: "tcp", Service: WellKnown(port)}
	d := net.Dialer{Timeout: opt.Timeout}
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	r.Latency = time.Since(start)
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			r.State = Filtered
		} else {
			r.State = Closed
		}
		return r
	}
	defer conn.Close()
	r.State = Open
	if opt.Banner {
		r.Banner = grabBanner(conn, opt.Timeout)
	}
	return r
}

func grabBanner(conn net.Conn, timeout time.Duration) string {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	s := strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return -1
	}, string(buf[:n]))
	return strings.TrimSpace(s)
}

var wellKnown = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
	110: "pop3", 143: "imap", 443: "https", 445: "smb", 993: "imaps",
	3000: "dev-http", 3306: "mysql", 3389: "rdp", 5432: "postgres",
	5900: "vnc", 6379: "redis", 8000: "http-alt", 8080: "http-alt",
	8443: "https-alt", 9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
}

// WellKnown returns a conventional service name for a port.
func WellKnown(port int) string { return wellKnown[port] }
