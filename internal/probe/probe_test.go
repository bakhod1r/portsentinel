package probe

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestScanFindsListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("SSH-2.0-test\r\n"))
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	res := ScanTCP(context.Background(), []string{"127.0.0.1"}, []int{port, 1}, Options{Timeout: time.Second, Concurrency: 4, Banner: true}, nil)
	if len(res) != 1 || res[0].Port != port {
		t.Fatalf("unexpected results: %+v", res)
	}
	if res[0].Banner != "SSH-2.0-test" {
		t.Fatalf("banner = %q", res[0].Banner)
	}
}
