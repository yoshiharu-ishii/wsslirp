package slirpstack_test

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/yoshiharu-ishii/wsslirp/internal/testutil"
	"github.com/yoshiharu-ishii/wsslirp/pkg/slirpstack"
)

// These benchmarks measure what the relay itself costs, with the outside
// world stubbed out (instant Ping, loopback echo server). Whatever they
// report is the floor a guest can ever see; anything on top comes from
// the transport or the guest.

// BenchmarkICMPFramePath: guest echo request frame in, echo reply frame
// out, with a Ping that returns immediately.
func BenchmarkICMPFramePath(b *testing.B) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hostEnd, guestEnd := testutil.FramePipe(ctx)
	cfg := slirpstack.Config{
		Ping: func(ctx context.Context, dst netip.Addr, seq int, data []byte) ([]byte, error) {
			return data, nil
		},
	}
	go slirpstack.Run(ctx, hostEnd, cfg)

	frame := echoFrame(b, net.IP{1, 1, 1, 1}, 1, 32)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := guestEnd.WriteFrame(frame); err != nil {
			b.Fatal(err)
		}
		for {
			got, err := guestEnd.ReadFrame()
			if err != nil {
				b.Fatal(err)
			}
			if isEchoReply(got) {
				break
			}
		}
	}
}

// BenchmarkTCPFramePath: one request/response exchange over an already
// open TCP flow, so it measures steady-state forwarding, not setup.
func BenchmarkTCPFramePath(b *testing.B) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hostEnd, guestEnd := testutil.FramePipe(ctx)
	cfg := slirpstack.Config{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.Dial("tcp", ln.Addr().String())
		},
	}
	go slirpstack.Run(ctx, hostEnd, cfg)
	g, err := testutil.NewGuest(ctx, guestEnd)
	if err != nil {
		b.Fatal(err)
	}
	defer g.Close()

	conn, err := g.DialTCP(ctx, netip.MustParseAddrPort("192.0.2.10:80"))
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Close()

	msg := make([]byte, 64)
	buf := make([]byte, 64)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := conn.Write(msg); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(conn, buf); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDispatchParse isolates the classification step of the receive
// loop: every frame is parsed by DHCP, then ICMP, then the ARP guard,
// each building its own gopacket.Packet.
func BenchmarkDispatchParse(b *testing.B) {
	frames := map[string][]byte{
		"tcp-ish": ipv4Frame(b),
		"icmp":    echoFrame(b, net.IP{1, 1, 1, 1}, 1, 32),
		"arp":     buildARPRequestBench(b),
	}
	for name, frame := range frames {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				// What the receive loop does today, in order.
				for range 3 {
					pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
					_ = pkt.Layer(layers.LayerTypeDHCPv4)
					_ = pkt.Layer(layers.LayerTypeICMPv4)
					_ = pkt.Layer(layers.LayerTypeARP)
				}
			}
		})
	}
}

// BenchmarkDispatchParseOnce is the same classification done with one
// lazy, non-copying parse, for comparison.
func BenchmarkDispatchParseOnce(b *testing.B) {
	frames := map[string][]byte{
		"tcp-ish": ipv4Frame(b),
		"icmp":    echoFrame(b, net.IP{1, 1, 1, 1}, 1, 32),
		"arp":     buildARPRequestBench(b),
	}
	opts := gopacket.DecodeOptions{Lazy: true, NoCopy: true}
	for name, frame := range frames {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, opts)
				_ = pkt.Layer(layers.LayerTypeDHCPv4)
				_ = pkt.Layer(layers.LayerTypeICMPv4)
				_ = pkt.Layer(layers.LayerTypeARP)
			}
		})
	}
}

// BenchmarkSystemPingSocket measures the cost of the ping socket itself,
// which systemPing opens fresh for every echo. Skipped where the OS
// refuses unprivileged ICMP sockets.
func BenchmarkSystemPingSocket(b *testing.B) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ping := slirpstack.SystemPingForTest()
	if _, err := ping(ctx, netip.MustParseAddr("127.0.0.1"), 1, []byte("x")); err != nil {
		b.Skipf("unprivileged ping unavailable: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		if _, err := ping(c, netip.MustParseAddr("127.0.0.1"), i, []byte("benchmark")); err != nil {
			cancel()
			b.Fatal(err)
		}
		cancel()
	}
}

func echoFrame(tb testing.TB, dst net.IP, seq uint16, payload int) []byte {
	tb.Helper()
	eth := layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x52, 0x55, 0x0a, 0x00, 0x02, 0x0f},
		DstMAC:       net.HardwareAddr{0x52, 0x55, 0x0a, 0x00, 0x02, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := layers.IPv4{
		Version: 4, TTL: 64, Protocol: layers.IPProtocolICMPv4,
		SrcIP: net.IP{10, 0, 2, 15}, DstIP: dst,
	}
	echo := layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		Id:       0x1234, Seq: seq,
	}
	return serializeBench(tb, &eth, &ip, &echo, gopacket.Payload(make([]byte, payload)))
}

func ipv4Frame(tb testing.TB) []byte {
	tb.Helper()
	eth := layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x52, 0x55, 0x0a, 0x00, 0x02, 0x0f},
		DstMAC:       net.HardwareAddr{0x52, 0x55, 0x0a, 0x00, 0x02, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := layers.IPv4{
		Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP,
		SrcIP: net.IP{10, 0, 2, 15}, DstIP: net.IP{93, 184, 216, 34},
	}
	tcp := layers.TCP{SrcPort: 49152, DstPort: 80, SYN: true, Window: 64240}
	tcp.SetNetworkLayerForChecksum(&ip)
	return serializeBench(tb, &eth, &ip, &tcp, gopacket.Payload(make([]byte, 100)))
}

func buildARPRequestBench(tb testing.TB) []byte {
	tb.Helper()
	mac := net.HardwareAddr{0x52, 0x55, 0x0a, 0x00, 0x02, 0x0f}
	eth := layers.Ethernet{
		SrcMAC:       mac,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4,
		HwAddressSize: 6, ProtAddressSize: 4, Operation: layers.ARPRequest,
		SourceHwAddress: mac, SourceProtAddress: net.IP{10, 0, 2, 15}.To4(),
		DstHwAddress: make([]byte, 6), DstProtAddress: net.IP{10, 0, 2, 2}.To4(),
	}
	return serializeBench(tb, &eth, &arp)
}

func serializeBench(tb testing.TB, ls ...gopacket.SerializableLayer) []byte {
	tb.Helper()
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ls...); err != nil {
		tb.Fatalf("serialize: %v", err)
	}
	return buf.Bytes()
}

func isEchoReply(frame []byte) bool {
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	ic, ok := pkt.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
	return ok && ic.TypeCode.Type() == layers.ICMPv4TypeEchoReply
}
