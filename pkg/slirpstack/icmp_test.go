package slirpstack_test

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/yoshiharu-ishii/wsslirp/pkg/slirpstack"
)

func buildEchoRequest(t *testing.T, dst net.IP, id, seq uint16, payload []byte) []byte {
	t.Helper()
	eth := layers.Ethernet{SrcMAC: guestMAC, DstMAC: gwMAC, EthernetType: layers.EthernetTypeIPv4}
	ip := layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolICMPv4, SrcIP: guestIP, DstIP: dst}
	icmp := layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		Id:       id,
		Seq:      seq,
	}
	return serialize(t, &eth, &ip, &icmp, gopacket.Payload(payload))
}

// TestOutboundPingProxied sends an echo request for a public address and
// expects it proxied through Config.Ping, with the reply frame carrying
// the guest's original id/seq and the payload the pinger returned.
func TestOutboundPingProxied(t *testing.T) {
	var pinged atomic.Value
	cfg := slirpstack.Config{
		Logf: t.Logf,
		Ping: func(ctx context.Context, dst netip.Addr, seq int, data []byte) ([]byte, error) {
			pinged.Store(dst.String())
			return data, nil // echo back what came in
		},
	}
	fio := startSlirp(t, cfg)

	payload := []byte("wsslirp-outbound-ping")
	if err := fio.WriteFrame(buildEchoRequest(t, net.IP{192, 0, 2, 10}, 0x77, 3, payload)); err != nil {
		t.Fatal(err)
	}
	pkt := awaitFrame(t, fio, "proxied echo reply", func(p gopacket.Packet) bool {
		ic, ok := p.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
		return ok && ic.TypeCode.Type() == layers.ICMPv4TypeEchoReply && ic.Id == 0x77 && ic.Seq == 3
	})
	ip := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ip.SrcIP.Equal(net.IP{192, 0, 2, 10}) || !ip.DstIP.Equal(guestIP) {
		t.Fatalf("reply %v -> %v, want 192.0.2.10 -> %v", ip.SrcIP, ip.DstIP, guestIP)
	}
	ic := pkt.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
	if string(ic.Payload) != string(payload) {
		t.Fatalf("reply payload = %q, want %q", ic.Payload, payload)
	}
	if got := pinged.Load(); got != "192.0.2.10" {
		t.Fatalf("pinger called with %v, want 192.0.2.10", got)
	}
}

// TestOutboundPingDenied verifies the egress policy covers ICMP: echoes
// to private destinations never reach the pinger, while the gateway
// keeps answering its own pings.
func TestOutboundPingDenied(t *testing.T) {
	var calls atomic.Int32
	cfg := slirpstack.Config{
		Logf: t.Logf,
		Ping: func(ctx context.Context, dst netip.Addr, seq int, data []byte) ([]byte, error) {
			calls.Add(1)
			return data, nil
		},
	}
	fio := startSlirp(t, cfg)

	// Teach the netstack the guest's MAC first; the gateway's echo reply
	// below needs it resolved.
	if err := fio.WriteFrame(buildARPRequest(t)); err != nil {
		t.Fatal(err)
	}
	if err := fio.WriteFrame(buildEchoRequest(t, net.IP{10, 99, 0, 1}, 1, 1, []byte("x"))); err != nil {
		t.Fatal(err)
	}
	// The gateway echo is processed after the denied one (Run reads
	// frames sequentially), so its reply doubles as the sync point.
	if err := fio.WriteFrame(buildEchoRequest(t, gwIP, 2, 2, []byte("y"))); err != nil {
		t.Fatal(err)
	}
	awaitFrame(t, fio, "gateway echo reply", func(p gopacket.Packet) bool {
		ic, ok := p.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
		return ok && ic.TypeCode.Type() == layers.ICMPv4TypeEchoReply && ic.Id == 2
	})
	if n := calls.Load(); n != 0 {
		t.Fatalf("pinger called %d times for a denied destination", n)
	}
}
