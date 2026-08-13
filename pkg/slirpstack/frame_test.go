package slirpstack_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/yoshiharu-ishii/wsslirp/internal/testutil"
	"github.com/yoshiharu-ishii/wsslirp/pkg/slirpstack"
)

var (
	guestMAC = net.HardwareAddr{0x52, 0x55, 0x0a, 0x00, 0x02, 0x0f}
	gwMAC    = net.HardwareAddr{0x52, 0x55, 0x0a, 0x00, 0x02, 0x02}
	guestIP  = net.IP{10, 0, 2, 15}
	gwIP     = net.IP{10, 0, 2, 2}
)

// startSlirp runs a slirpstack on one end of a frame pipe and returns the
// guest-side end.
func startSlirp(t *testing.T, cfg slirpstack.Config) slirpstack.FrameIO {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	hostEnd, guestEnd := testutil.FramePipe(ctx)
	go slirpstack.Run(ctx, hostEnd, cfg)
	return guestEnd
}

// awaitFrame reads frames until match returns true, answering nothing else.
func awaitFrame(t *testing.T, fio slirpstack.FrameIO, what string, match func(gopacket.Packet) bool) gopacket.Packet {
	t.Helper()
	found := make(chan gopacket.Packet, 1)
	go func() {
		for {
			frame, err := fio.ReadFrame()
			if err != nil {
				return
			}
			pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
			if match(pkt) {
				found <- pkt
				return
			}
		}
	}()
	select {
	case pkt := <-found:
		return pkt
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		return nil
	}
}

func serialize(t *testing.T, ls ...gopacket.SerializableLayer) []byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ls...); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return buf.Bytes()
}

func buildDHCP(t *testing.T, msgType layers.DHCPMsgType, xid uint32) []byte {
	eth := layers.Ethernet{
		SrcMAC:       guestMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.IPv4zero,
		DstIP:    net.IPv4bcast,
	}
	udp := layers.UDP{SrcPort: 68, DstPort: 67}
	udp.SetNetworkLayerForChecksum(&ip)
	dhcp := layers.DHCPv4{
		Operation:    layers.DHCPOpRequest,
		HardwareType: layers.LinkTypeEthernet,
		Xid:          xid,
		ClientHWAddr: guestMAC,
		Options: layers.DHCPOptions{
			layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(msgType)}),
		},
	}
	return serialize(t, &eth, &ip, &udp, &dhcp)
}

func dhcpOption(d *layers.DHCPv4, opt layers.DHCPOpt) []byte {
	for _, o := range d.Options {
		if o.Type == opt {
			return o.Data
		}
	}
	return nil
}

func TestDHCPHandshake(t *testing.T) {
	fio := startSlirp(t, slirpstack.Config{Logf: t.Logf})

	steps := []struct {
		send layers.DHCPMsgType
		want layers.DHCPMsgType
		xid  uint32
	}{
		{layers.DHCPMsgTypeDiscover, layers.DHCPMsgTypeOffer, 0x11111111},
		{layers.DHCPMsgTypeRequest, layers.DHCPMsgTypeAck, 0x22222222},
	}
	for _, st := range steps {
		if err := fio.WriteFrame(buildDHCP(t, st.send, st.xid)); err != nil {
			t.Fatal(err)
		}
		pkt := awaitFrame(t, fio, st.want.String(), func(p gopacket.Packet) bool {
			d, ok := p.Layer(layers.LayerTypeDHCPv4).(*layers.DHCPv4)
			return ok && d.Operation == layers.DHCPOpReply && d.Xid == st.xid
		})
		d := pkt.Layer(layers.LayerTypeDHCPv4).(*layers.DHCPv4)
		if got := dhcpOption(d, layers.DHCPOptMessageType); len(got) != 1 || layers.DHCPMsgType(got[0]) != st.want {
			t.Fatalf("message type = %v, want %v", got, st.want)
		}
		if !d.YourClientIP.Equal(guestIP) {
			t.Errorf("yiaddr = %v, want %v", d.YourClientIP, guestIP)
		}
		if got := dhcpOption(d, layers.DHCPOptRouter); !net.IP(got).Equal(gwIP) {
			t.Errorf("router = %v, want %v", got, gwIP)
		}
		if got := dhcpOption(d, layers.DHCPOptDNS); !net.IP(got).Equal(net.IP{10, 0, 2, 3}) {
			t.Errorf("dns = %v, want 10.0.2.3", got)
		}
		if got := dhcpOption(d, layers.DHCPOptSubnetMask); !net.IP(got).Equal(net.IP{255, 255, 255, 0}) {
			t.Errorf("mask = %v, want 255.255.255.0", got)
		}
	}
}

// TestARPForGuestIPStaysSilent verifies address-conflict probes are not
// answered: an ARP request for the guest's own IP must get no reply
// (mTCP aborts with "IP address conflict!" if anyone answers), while the
// gateway keeps answering for itself.
func TestARPForGuestIPStaysSilent(t *testing.T) {
	fio := startSlirp(t, slirpstack.Config{Logf: t.Logf})

	arpFor := func(target net.IP, srcIP net.IP) []byte {
		eth := layers.Ethernet{
			SrcMAC:       guestMAC,
			DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			EthernetType: layers.EthernetTypeARP,
		}
		arp := layers.ARP{
			AddrType:          layers.LinkTypeEthernet,
			Protocol:          layers.EthernetTypeIPv4,
			HwAddressSize:     6,
			ProtAddressSize:   4,
			Operation:         layers.ARPRequest,
			SourceHwAddress:   guestMAC,
			SourceProtAddress: srcIP.To4(),
			DstHwAddress:      make([]byte, 6),
			DstProtAddress:    target.To4(),
		}
		return serialize(t, &eth, &arp)
	}

	// RFC 5227の衝突検査そのもの: 送り元0.0.0.0で自分のIPを尋ねる
	if err := fio.WriteFrame(arpFor(guestIP, net.IPv4zero)); err != nil {
		t.Fatal(err)
	}
	// 続けてゲートウェイ宛 — こちらの応答が「沈黙の同期点」になる
	if err := fio.WriteFrame(arpFor(gwIP, guestIP)); err != nil {
		t.Fatal(err)
	}
	pkt := awaitFrame(t, fio, "gateway ARP reply", func(p gopacket.Packet) bool {
		a, ok := p.Layer(layers.LayerTypeARP).(*layers.ARP)
		return ok && a.Operation == layers.ARPReply
	})
	a := pkt.Layer(layers.LayerTypeARP).(*layers.ARP)
	if !net.IP(a.SourceProtAddress).Equal(gwIP) {
		t.Fatalf("ARP応答の名乗りが %v — ゲスト宛ARPに代返している疑い", net.IP(a.SourceProtAddress))
	}
}

func buildARPRequest(t *testing.T) []byte {
	eth := layers.Ethernet{
		SrcMAC:       guestMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   guestMAC,
		SourceProtAddress: guestIP.To4(),
		DstHwAddress:      make([]byte, 6),
		DstProtAddress:    gwIP.To4(),
	}
	return serialize(t, &eth, &arp)
}

func TestARPAndPing(t *testing.T) {
	fio := startSlirp(t, slirpstack.Config{Logf: t.Logf})

	if err := fio.WriteFrame(buildARPRequest(t)); err != nil {
		t.Fatal(err)
	}
	pkt := awaitFrame(t, fio, "ARP reply", func(p gopacket.Packet) bool {
		a, ok := p.Layer(layers.LayerTypeARP).(*layers.ARP)
		return ok && a.Operation == layers.ARPReply && net.IP(a.SourceProtAddress).Equal(gwIP)
	})
	a := pkt.Layer(layers.LayerTypeARP).(*layers.ARP)
	if got := net.HardwareAddr(a.SourceHwAddress); got.String() != gwMAC.String() {
		t.Fatalf("ARP reply MAC = %v, want %v", got, gwMAC)
	}

	eth := layers.Ethernet{SrcMAC: guestMAC, DstMAC: gwMAC, EthernetType: layers.EthernetTypeIPv4}
	ip := layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolICMPv4, SrcIP: guestIP, DstIP: gwIP}
	icmp := layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		Id:       7,
		Seq:      1,
	}
	payload := gopacket.Payload([]byte("ping-wsslirp"))
	if err := fio.WriteFrame(serialize(t, &eth, &ip, &icmp, payload)); err != nil {
		t.Fatal(err)
	}
	pkt = awaitFrame(t, fio, "ICMP echo reply", func(p gopacket.Packet) bool {
		ic, ok := p.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
		return ok && ic.TypeCode.Type() == layers.ICMPv4TypeEchoReply && ic.Id == 7 && ic.Seq == 1
	})
	rip := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !rip.SrcIP.Equal(gwIP) || !rip.DstIP.Equal(guestIP) {
		t.Fatalf("echo reply %v -> %v, want %v -> %v", rip.SrcIP, rip.DstIP, gwIP, guestIP)
	}
}
