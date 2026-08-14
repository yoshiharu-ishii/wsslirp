package slirpstack

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	pingTimeout = 4 * time.Second
	// maxPings caps concurrent outbound echoes; beyond it requests are
	// dropped and the guest sees ordinary packet loss.
	maxPings = 64
)

// maybeHandleICMP intercepts guest echo requests bound for the outside
// world and proxies them over an unprivileged ping socket, at the frame
// level like DHCP. Echoes to the stack's own addresses fall through to
// the netstack, which answers them itself (gateway ping).
func (ns *netstack) maybeHandleICMP(pkt gopacket.Packet, fio FrameIO) bool {
	eth, ok := pkt.LinkLayer().(*layers.Ethernet)
	if !ok {
		return false
	}
	ip, ok := pkt.NetworkLayer().(*layers.IPv4)
	if !ok {
		return false
	}
	req, ok := pkt.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
	if !ok || req.TypeCode.Type() != layers.ICMPv4TypeEchoRequest {
		return false
	}
	dst, ok := netip.AddrFromSlice(ip.DstIP.To4())
	if !ok || dst == ns.cfg.GatewayIP || dst == ns.cfg.DNSIP {
		return false
	}
	src, _ := netip.AddrFromSlice(ip.SrcIP.To4())
	if !ns.cfg.allowDest(dst) {
		ns.cfg.Logf("icmp deny  %s -> %s", src, dst)
		return true
	}
	select {
	case ns.pings <- struct{}{}:
	default:
		ns.cfg.Logf("icmp drop  %s -> %s (over %d pings in flight)", src, dst, maxPings)
		return true
	}
	go ns.proxyPing(fio, echoReq{
		guestMAC: append(net.HardwareAddr(nil), eth.SrcMAC...),
		src:      src,
		dst:      dst,
		id:       req.Id,
		seq:      req.Seq,
		payload:  append([]byte(nil), req.Payload...),
	})
	return true
}

// echoReq is everything proxyPing needs from a guest echo request,
// copied out of the parsed layers. The layers point into the frame
// buffer, whose lifetime ends when dispatch returns, so nothing from
// them may cross this goroutine boundary by reference.
type echoReq struct {
	guestMAC net.HardwareAddr
	src, dst netip.Addr
	id, seq  uint16
	payload  []byte
}

// proxyPing performs one echo round-trip and writes the reply frame back
// to the guest. Errors (timeouts, unreachable ping sockets) surface to
// the guest as packet loss, which is what ping expects.
func (ns *netstack) proxyPing(fio FrameIO, req echoReq) {
	defer func() { <-ns.pings }()
	ctx, cancel := context.WithTimeout(ns.ctx, pingTimeout)
	defer cancel()
	ns.flowf("icmp echo  %s -> %s (seq=%d, %d B)", req.src, req.dst, req.seq, len(req.payload))
	start := time.Now()
	data, err := ns.cfg.Ping(ctx, req.dst, int(req.seq), req.payload)
	if err != nil {
		ns.cfg.Logf("icmp fail  %s -> %s (seq=%d): %v", req.src, req.dst, req.seq, err)
		return
	}
	ns.flowf("icmp reply %s <- %s (seq=%d, %s)", req.src, req.dst, req.seq, formatDur(time.Since(start)))
	eth := layers.Ethernet{
		SrcMAC:       ns.cfg.GatewayMAC,
		DstMAC:       req.guestMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolICMPv4,
		SrcIP:    net.IP(req.dst.AsSlice()),
		DstIP:    net.IP(req.src.AsSlice()),
	}
	reply := layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0),
		Id:       req.id,
		Seq:      req.seq,
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &ip, &reply, gopacket.Payload(data)); err != nil {
		ns.cfg.Logf("icmp: build reply: %v", err)
		return
	}
	if err := fio.WriteFrame(buf.Bytes()); err != nil {
		ns.cfg.Logf("icmp: write reply: %v", err)
	}
}

// systemPing is the default Config.Ping: one echo over an unprivileged
// ICMP socket (SOCK_DGRAM + IPPROTO_ICMP). Works out of the box on
// macOS; on Linux the daemon's group must be inside the sysctl
// net.ipv4.ping_group_range. The kernel rewrites the echo ID to demux
// replies per socket, so matching the sequence number is enough.
func systemPing(ctx context.Context, dst netip.Addr, seq int, data []byte) ([]byte, error) {
	c, err := icmp.ListenPacket("udp4", "")
	if err != nil {
		return nil, err
	}
	defer c.Close()
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{Seq: seq, Data: data},
	}
	wb, err := msg.Marshal(nil)
	if err != nil {
		return nil, err
	}
	if _, err := c.WriteTo(wb, &net.UDPAddr{IP: dst.AsSlice()}); err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		c.SetReadDeadline(dl)
	}
	rb := make([]byte, frameMTU)
	for {
		n, _, err := c.ReadFrom(rb)
		if err != nil {
			return nil, err
		}
		m, err := icmp.ParseMessage(1, rb[:n]) // 1 = protocol number of ICMPv4
		if err != nil {
			continue
		}
		if echo, ok := m.Body.(*icmp.Echo); ok && m.Type == ipv4.ICMPTypeEchoReply && echo.Seq == seq {
			return echo.Data, nil
		}
	}
}
