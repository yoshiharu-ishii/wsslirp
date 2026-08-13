package slirpstack_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/yoshiharu-ishii/wsslirp/internal/testutil"
	"github.com/yoshiharu-ishii/wsslirp/pkg/slirpstack"
)

// logSink collects log lines and lets a test block until one appears.
type logSink struct {
	t     *testing.T
	mu    sync.Mutex
	lines []string
}

func (s *logSink) Logf(format string, args ...any) {
	line := strings.TrimSpace(fmt.Sprintf(format, args...))
	s.mu.Lock()
	s.lines = append(s.lines, line)
	s.mu.Unlock()
	s.t.Log("LOG:", line)
}

// await waits for a line containing every one of want.
func (s *logSink) await(t *testing.T, want ...string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		for _, line := range s.lines {
			if containsAll(line, want) {
				s.mu.Unlock()
				return line
			}
		}
		s.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t.Fatalf("no log line with %q; got:\n%s", want, strings.Join(s.lines, "\n"))
	return ""
}

// refute fails if any line contains all of want.
func (s *logSink) refute(t *testing.T, want ...string) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, line := range s.lines {
		if containsAll(line, want) {
			t.Fatalf("unexpected log line %q (matched %q)", line, want)
		}
	}
}

func containsAll(line string, want []string) bool {
	for _, w := range want {
		if !strings.Contains(line, w) {
			return false
		}
	}
	return true
}

// buildEcho hand-builds a guest ICMP echo request frame for dst.
func buildEcho(t *testing.T, dst net.IP, seq uint16) []byte {
	t.Helper()
	eth := layers.Ethernet{SrcMAC: guestMAC, DstMAC: gwMAC, EthernetType: layers.EthernetTypeIPv4}
	ip := layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolICMPv4, SrcIP: guestIP, DstIP: dst}
	echo := layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		Id:       0x1234,
		Seq:      seq,
	}
	return serialize(t, &eth, &ip, &echo, gopacket.Payload([]byte("flowlog")))
}

// TestFlowLogTCP checks the audit shape of a TCP flow: an open line with
// the guest on the left of the arrow, and a close line carrying bytes
// tagged by direction.
func TestFlowLogTCP(t *testing.T) {
	echo := startEcho(t)
	sink := &logSink{t: t}
	cfg := slirpstack.Config{
		LogFlows: true,
		Logf:     sink.Logf,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.Dial("tcp", echo.Addr().String())
		},
	}
	g := startGuest(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := g.DialTCP(ctx, netip.MustParseAddrPort("192.0.2.10:80"))
	if err != nil {
		t.Fatalf("guest dial: %v", err)
	}
	msg := []byte("0123456789")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}

	open := sink.await(t, "tcp open", "10.0.2.15:", "-> 192.0.2.10:80")
	t.Logf("open line: %s", open)

	conn.Close()
	closed := sink.await(t, "tcp close", "-> 192.0.2.10:80", "-> 10 B", "<- 10 B")
	t.Logf("close line: %s", closed)

	// The source port must be identical on both lines, or flows cannot
	// be paired up in an audit.
	if openPort, closePort := srcPort(t, open), srcPort(t, closed); openPort != closePort {
		t.Fatalf("source port differs: open %s, close %s", openPort, closePort)
	}
}

// srcPort extracts the guest port from "... 10.0.2.15:NNNNN -> ...".
func srcPort(t *testing.T, line string) string {
	t.Helper()
	i := strings.Index(line, "10.0.2.15:")
	if i < 0 {
		t.Fatalf("no guest address in %q", line)
	}
	rest := line[i+len("10.0.2.15:"):]
	if j := strings.IndexAny(rest, " "); j >= 0 {
		return rest[:j]
	}
	return rest
}

// TestFlowLogDeniedAndOff covers the two policy-relevant cases: a denial
// is logged even with flow logging off, and ordinary flows are not.
func TestFlowLogDeniedAndOff(t *testing.T) {
	echo := startEcho(t)
	sink := &logSink{t: t}
	cfg := slirpstack.Config{
		LogFlows: false,
		Logf:     sink.Logf,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.Dial("tcp", echo.Addr().String())
		},
	}
	g := startGuest(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := g.DialTCP(ctx, netip.MustParseAddrPort("10.99.0.1:80")); err == nil {
		t.Fatal("dial to private destination succeeded")
	}
	sink.await(t, "tcp deny", "10.0.2.15:", "-> 10.99.0.1:80")

	conn, err := g.DialTCP(ctx, netip.MustParseAddrPort("192.0.2.10:80"))
	if err != nil {
		t.Fatal(err)
	}
	conn.Write([]byte("x"))
	time.Sleep(200 * time.Millisecond)
	sink.refute(t, "tcp open")
	conn.Close()
}

// TestFlowLogUDPAndICMP covers the DNS annotation and the echo/reply
// pair, which is the one place the arrow points back at the guest.
func TestFlowLogUDPAndICMP(t *testing.T) {
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
			upstream.WriteTo(buf[:n], addr)
		}
	}()

	sink := &logSink{t: t}
	cfg := slirpstack.Config{
		LogFlows:    true,
		Logf:        sink.Logf,
		UpstreamDNS: upstream.LocalAddr().String(),
		Ping: func(ctx context.Context, dst netip.Addr, seq int, data []byte) ([]byte, error) {
			return data, nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	hostEnd, guestEnd := testutil.FramePipe(ctx)
	go slirpstack.Run(ctx, hostEnd, cfg)
	g, err := testutil.NewGuest(ctx, guestEnd)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(g.Close)

	dns, err := g.DialUDP(netip.MustParseAddrPort("10.0.2.3:53"))
	if err != nil {
		t.Fatal(err)
	}
	defer dns.Close()
	if _, err := dns.Write(make([]byte, 20)); err != nil {
		t.Fatal(err)
	}
	sink.await(t, "udp open", "10.0.2.15:", "-> 10.0.2.3:53", "dns via "+upstream.LocalAddr().String())

	// ICMP goes in at the frame level, so hand-build the echo request.
	if err := guestEnd.WriteFrame(buildEcho(t, net.IP{1, 1, 1, 1}, 9)); err != nil {
		t.Fatal(err)
	}
	sink.await(t, "icmp echo", "10.0.2.15 -> 1.1.1.1", "seq=9")
	sink.await(t, "icmp reply", "10.0.2.15 <- 1.1.1.1", "seq=9")
}
