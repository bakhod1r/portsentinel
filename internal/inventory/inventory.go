// Package inventory lists local listening sockets from /proc and maps them to processes.
package inventory

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Socket is a local listening socket.
type Socket struct {
	Proto   string `json:"proto"`
	Addr    string `json:"addr"`
	Port    int    `json:"port"`
	Inode   uint64 `json:"inode"`
	PID     int    `json:"pid,omitempty"`
	Process string `json:"process,omitempty"`
}

// Public reports whether the socket listens on a non-loopback address.
func (s Socket) Public() bool {
	ip := net.ParseIP(s.Addr)
	return ip == nil || !ip.IsLoopback()
}

const tcpListen = "0A"

// Listening returns TCP listening sockets (IPv4 + IPv6) with process info when readable.
func Listening(procRoot string) ([]Socket, error) {
	var all []Socket
	for _, f := range []struct{ file, proto string }{{"net/tcp", "tcp"}, {"net/tcp6", "tcp6"}} {
		fh, err := os.Open(filepath.Join(procRoot, f.file))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		socks, err := ParseProcNet(fh, f.proto)
		fh.Close()
		if err != nil {
			return nil, err
		}
		all = append(all, socks...)
	}
	owners := inodeOwners(procRoot)
	for i := range all {
		if o, ok := owners[all[i].Inode]; ok {
			all[i].PID, all[i].Process = o.pid, o.name
		}
	}
	return all, nil
}

// ParseProcNet parses /proc/net/tcp{,6} content and keeps LISTEN sockets.
func ParseProcNet(r io.Reader, proto string) ([]Socket, error) {
	var out []Socket
	sc := bufio.NewScanner(r)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 || fields[3] != tcpListen {
			continue
		}
		addr, port, err := parseHexAddr(fields[1])
		if err != nil {
			return nil, err
		}
		inode, _ := strconv.ParseUint(fields[9], 10, 64)
		out = append(out, Socket{Proto: proto, Addr: addr, Port: port, Inode: inode})
	}
	return out, sc.Err()
}

func parseHexAddr(s string) (string, int, error) {
	i := strings.IndexByte(s, ':')
	if i < 0 {
		return "", 0, fmt.Errorf("bad address %q", s)
	}
	raw, err := hex.DecodeString(s[:i])
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.ParseUint(s[i+1:], 16, 16)
	if err != nil {
		return "", 0, err
	}
	// The kernel prints each 32-bit word in host (little-endian) order.
	for w := 0; w+4 <= len(raw); w += 4 {
		raw[w], raw[w+1], raw[w+2], raw[w+3] = raw[w+3], raw[w+2], raw[w+1], raw[w]
	}
	return net.IP(raw).String(), int(port), nil
}

type owner struct {
	pid  int
	name string
}

func inodeOwners(procRoot string) map[uint64]owner {
	out := map[uint64]owner{}
	dirs, _ := os.ReadDir(procRoot)
	for _, d := range dirs {
		pid, err := strconv.Atoi(d.Name())
		if err != nil {
			continue
		}
		fdDir := filepath.Join(procRoot, d.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		var name string
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			inode, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]"), 10, 64)
			if err != nil {
				continue
			}
			if name == "" {
				b, _ := os.ReadFile(filepath.Join(procRoot, d.Name(), "comm"))
				name = strings.TrimSpace(string(b))
			}
			out[inode] = owner{pid, name}
		}
	}
	return out
}
