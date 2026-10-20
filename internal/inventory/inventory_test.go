package inventory

import (
	"strings"
	"testing"
)

const sample = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1234 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 5678 1 0000000000000000 100 0 0 10 0
   2: 0100007F:1F90 0100007F:A000 01 00000000:00000000 00:00000000 00000000     0        0 9999 1 0000000000000000 100 0 0 10 0
`

func TestParseProcNet(t *testing.T) {
	socks, err := ParseProcNet(strings.NewReader(sample), "tcp")
	if err != nil {
		t.Fatal(err)
	}
	if len(socks) != 2 {
		t.Fatalf("want 2 listeners, got %d", len(socks))
	}
	if socks[0].Addr != "0.0.0.0" || socks[0].Port != 22 || !socks[0].Public() {
		t.Fatalf("bad socket 0: %+v", socks[0])
	}
	if socks[1].Addr != "127.0.0.1" || socks[1].Port != 8080 || socks[1].Public() {
		t.Fatalf("bad socket 1: %+v", socks[1])
	}
}
