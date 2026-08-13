package slirpstack_test

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yoshiharu-ishii/wsslirp/internal/testutil"
	"github.com/yoshiharu-ishii/wsslirp/pkg/slirpstack"
)

// startEcho runs a local TCP echo server for the relay to dial.
func startEcho(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	return ln
}

func startGuest(t *testing.T, cfg slirpstack.Config) *testutil.Guest {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	hostEnd, guestEnd := testutil.FramePipe(ctx)
	go slirpstack.Run(ctx, hostEnd, cfg)
	g, err := testutil.NewGuest(ctx, guestEnd)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(g.Close)
	return g
}

// TestTCPThroughSlirp drives a full path: guest netstack -> Ethernet frames
// -> slirp TCP termination -> host dial -> echo server, and back.
func TestTCPThroughSlirp(t *testing.T) {
	echo := startEcho(t)
	var dialed atomic.Value
	cfg := slirpstack.Config{
		Logf: t.Logf,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialed.Store(network + "/" + addr)
			return net.Dial("tcp", echo.Addr().String())
		},
	}
	g := startGuest(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// 192.0.2.10 is TEST-NET-1: public by classification, so it passes the
	// egress policy; the dial hook redirects it to the local echo server.
	conn, err := g.DialTCP(ctx, netip.MustParseAddrPort("192.0.2.10:9999"))
	if err != nil {
		t.Fatalf("guest dial: %v", err)
	}
	defer conn.Close()

	msg := []byte("hello from the guest side")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("echo read: %v", err)
	}
	if string(got) != string(msg) {
		t.Fatalf("echo = %q, want %q", got, msg)
	}
	if d := dialed.Load(); d != "tcp/192.0.2.10:9999" {
		t.Fatalf("relay dialed %v, want tcp/192.0.2.10:9999", d)
	}
}

// TestTCPHalfClose covers FIN propagation: the guest sends its request
// and shuts down the write side; the server replies only after seeing
// EOF. Without half-close support the relay tears down both directions
// on the first EOF and the response is lost.
func TestTCPHalfClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				data, _ := io.ReadAll(c) // wait for the client's FIN
				c.Write(append([]byte("resp:"), data...))
				c.Close()
			}()
		}
	}()

	cfg := slirpstack.Config{
		Logf: t.Logf,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.Dial("tcp", ln.Addr().String())
		},
	}
	g := startGuest(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := g.DialTCP(ctx, netip.MustParseAddrPort("192.0.2.10:9999"))
	if err != nil {
		t.Fatalf("guest dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatalf("guest CloseWrite: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read response after half-close: %v", err)
	}
	if string(got) != "resp:ping" {
		t.Fatalf("response = %q, want %q", got, "resp:ping")
	}
}

// TestEgressDenied verifies the SSRF guard: private destinations are
// refused with a RST before any host dial happens.
func TestEgressDenied(t *testing.T) {
	var dials atomic.Int32
	cfg := slirpstack.Config{
		Logf: t.Logf,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dials.Add(1)
			return nil, context.Canceled
		},
	}
	g := startGuest(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := g.DialTCP(ctx, netip.MustParseAddrPort("10.99.0.1:80"))
	if err == nil {
		t.Fatal("dial to private destination succeeded, want refusal")
	}
	if n := dials.Load(); n != 0 {
		t.Fatalf("relay attempted %d host dials for a denied destination", n)
	}
}

// TestDNSThroughSlirp sends a query to the virtual resolver 10.0.2.3 and
// expects it forwarded to the configured upstream.
func TestDNSThroughSlirp(t *testing.T) {
	upstream, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { upstream.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := upstream.ReadFrom(buf)
			if err != nil {
				return
			}
			if n >= 3 {
				buf[2] |= 0x80 // set QR: pretend to answer
			}
			upstream.WriteTo(buf[:n], addr)
		}
	}()

	cfg := slirpstack.Config{Logf: t.Logf, UpstreamDNS: upstream.LocalAddr().String()}
	g := startGuest(t, cfg)

	conn, err := g.DialUDP(netip.MustParseAddrPort("10.0.2.3:53"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	query := make([]byte, 17)
	query[0], query[1] = 0xbe, 0xef // DNS ID
	if _, err := conn.Write(query); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 1500)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(reply)
	if err != nil {
		t.Fatalf("dns reply: %v", err)
	}
	if n != len(query) || reply[0] != 0xbe || reply[1] != 0xef {
		t.Fatalf("reply mismatch: % x", reply[:n])
	}
	if reply[2]&0x80 == 0 {
		t.Fatal("QR bit not set; reply did not come from upstream")
	}
}
