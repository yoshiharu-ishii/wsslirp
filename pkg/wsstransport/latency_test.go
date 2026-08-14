package wsstransport_test

import (
	"context"
	"net"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/coder/websocket"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/yoshiharu-ishii/wsslirp/pkg/slirpstack"
	"github.com/yoshiharu-ishii/wsslirp/pkg/wsstransport"
)

// BenchmarkICMPOverWebSocket measures the same echo round trip as
// BenchmarkICMPFramePath, but through a real WebSocket over loopback.
// The difference between the two is what the transport costs.
func BenchmarkICMPOverWebSocket(b *testing.B) {
	h := &wsstransport.Handler{
		Config: slirpstack.Config{
			Ping: func(ctx context.Context, dst netip.Addr, seq int, data []byte) ([]byte, error) {
				return data, nil
			},
		},
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, _, err := websocket.Dial(ctx, strings.Replace(srv.URL, "http://", "ws://", 1), nil)
	if err != nil {
		b.Fatal(err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")
	c.SetReadLimit(1 << 16)
	fio := wsstransport.NewConnFrameIO(ctx, c)

	frame := echoFrameBench(b, 32)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := fio.WriteFrame(frame); err != nil {
			b.Fatal(err)
		}
		for {
			got, err := fio.ReadFrame()
			if err != nil {
				b.Fatal(err)
			}
			pkt := gopacket.NewPacket(got, layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
			if ic, ok := pkt.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4); ok &&
				ic.TypeCode.Type() == layers.ICMPv4TypeEchoReply {
				break
			}
		}
	}
}

func echoFrameBench(tb testing.TB, payload int) []byte {
	tb.Helper()
	eth := layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x52, 0x55, 0x0a, 0x00, 0x02, 0x0f},
		DstMAC:       net.HardwareAddr{0x52, 0x55, 0x0a, 0x00, 0x02, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := layers.IPv4{
		Version: 4, TTL: 64, Protocol: layers.IPProtocolICMPv4,
		SrcIP: net.IP{10, 0, 2, 15}, DstIP: net.IP{1, 1, 1, 1},
	}
	echo := layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		Id:       0x1234, Seq: 1,
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &ip, &echo, gopacket.Payload(make([]byte, payload))); err != nil {
		tb.Fatal(err)
	}
	return buf.Bytes()
}
