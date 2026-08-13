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
func (ns *netstack) maybeHandleICMP(frame []byte, fio FrameIO) bool {
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
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
	if !ns.cfg.allowDest(dst) {
		ns.cfg.Logf("icmp: denied egress to %s", dst)
		return true
	}
	select {
	case ns.pings <- struct{}{}:
	default:
		ns.cfg.Logf("icmp: over %d pings in flight, dropping echo to %s", maxPings, dst)
		return true
	}
	go ns.proxyPing(fio, dst, eth, ip, req)
	return true
}

// proxyPing performs one echo round-trip and writes the reply frame back
// to the guest. Errors (timeouts, unreachable ping sockets) surface to
// the guest as packet loss, which is what ping expects.
func (ns *netstack) proxyPing(fio FrameIO, dst netip.Addr, ethReq *layers.Ethernet, ipReq *layers.IPv4, req *layers.ICMPv4) {
	defer func() { <-ns.pings }()
	ctx, cancel := context.WithTimeout(ns.ctx, pingTimeout)
	defer cancel()
	data, err := ns.cfg.Ping(ctx, dst, int(req.Seq), req.Payload)
	if err != nil {
		ns.cfg.Logf("icmp: echo %s: %v", dst, err)
		return
	}
	eth := layers.Ethernet{
		SrcMAC:       ns.cfg.GatewayMAC,
		DstMAC:       ethReq.SrcMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolICMPv4,
		SrcIP:    ipReq.DstIP,
		DstIP:    ipReq.SrcIP,
	}
	reply := layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0),
		Id:       req.Id,
		Seq:      req.Seq,
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
