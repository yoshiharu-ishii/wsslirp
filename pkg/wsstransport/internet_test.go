package wsstransport_test

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/yoshiharu-ishii/wsslirp/internal/testutil"
	"github.com/yoshiharu-ishii/wsslirp/pkg/wsstransport"
)

// TestRealInternet exercises a running wsslirpd against the real network:
// a DNS query to the virtual resolver and an HTTP GET to example.com.
// Enable it by pointing WSSLIRP_E2E_URL at a live daemon, e.g.
//
//	WSSLIRP_E2E_URL='ws://127.0.0.1:8098/net?token=test' go test ./pkg/wsstransport -run RealInternet -v
func TestRealInternet(t *testing.T) {
	url := os.Getenv("WSSLIRP_E2E_URL")
	if url == "" {
		t.Skip("set WSSLIRP_E2E_URL to run the real-internet test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	c, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatalf("websocket dial %s: %v", url, err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")
	c.SetReadLimit(1 << 16)

	g, err := testutil.NewGuest(ctx, wsstransport.NewConnFrameIO(ctx, c))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(g.Close)

	// DNS: guest -> 10.0.2.3:53 -> upstream resolver.
	dnsConn, err := g.DialUDP(netip.MustParseAddrPort("10.0.2.3:53"))
	if err != nil {
		t.Fatal(err)
	}
	defer dnsConn.Close()
	query := []byte{0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split("example.com", ".") {
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	query = append(query, 0, 0, 1, 0, 1) // QTYPE=A, QCLASS=IN
	if _, err := dnsConn.Write(query); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 1500)
	dnsConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := dnsConn.Read(reply)
	if err != nil {
		t.Fatalf("dns reply: %v", err)
	}
	if n < 12 || reply[0] != 0xab || reply[1] != 0xcd || reply[2]&0x80 == 0 {
		t.Fatalf("bad dns reply: % x", reply[:n])
	}
	ancount := binary.BigEndian.Uint16(reply[6:8])
	if ancount == 0 {
		t.Fatal("dns reply has no answers")
	}
	t.Logf("dns: example.com resolved through the relay (%d answers)", ancount)

	// HTTP: resolve on the host side, then GET through the guest TCP path.
	ips, err := net.LookupIP("example.com")
	if err != nil {
		t.Fatal(err)
	}
	var target netip.Addr
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			target = netip.AddrFrom4([4]byte(v4))
			break
		}
	}
	if !target.IsValid() {
		t.Skip("example.com has no IPv4 address")
	}
	conn, err := g.DialTCP(ctx, netip.AddrPortFrom(target, 80))
	if err != nil {
		t.Fatalf("guest dial %s:80: %v", target, err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err = conn.Read(buf)
	if err != nil {
		t.Fatalf("http read: %v", err)
	}
	status := strings.SplitN(string(buf[:n]), "\r\n", 2)[0]
	if !strings.HasPrefix(status, "HTTP/1.1 ") {
		t.Fatalf("unexpected response: %q", status)
	}
	t.Logf("http: %s from example.com via %s", status, target)
}
