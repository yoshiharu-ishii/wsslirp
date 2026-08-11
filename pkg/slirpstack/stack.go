package slirpstack

import (
	"context"
	"fmt"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const (
	nicID    = tcpip.NICID(1)
	frameMTU = 1514 // ethernet frame; the ethernet wrapper exposes 1500 to L3
)

type netstack struct {
	ctx context.Context
	cfg Config
	s   *stack.Stack
	ep  *channel.Endpoint
}

func newNetstack(ctx context.Context, cfg Config) (*netstack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			arp.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
		},
	})
	ep := channel.New(512, frameMTU, tcpip.LinkAddress(cfg.GatewayMAC))
	ns := &netstack{ctx: ctx, cfg: cfg, s: s, ep: ep}

	if err := s.CreateNIC(nicID, ethernet.New(ep)); err != nil {
		return nil, fmt.Errorf("CreateNIC: %s", err)
	}
	// Promiscuous: deliver packets addressed to any IP (the guest's real
	// destinations) to our transport handlers. Spoofing: let us answer
	// with those foreign addresses as our source.
	if err := s.SetPromiscuousMode(nicID, true); err != nil {
		return nil, fmt.Errorf("SetPromiscuousMode: %s", err)
	}
	if err := s.SetSpoofing(nicID, true); err != nil {
		return nil, fmt.Errorf("SetSpoofing: %s", err)
	}
	for _, ip := range []tcpip.Address{
		tcpip.AddrFrom4(cfg.GatewayIP.As4()),
		tcpip.AddrFrom4(cfg.DNSIP.As4()),
	} {
		addr := tcpip.ProtocolAddress{
			Protocol: ipv4.ProtocolNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   ip,
				PrefixLen: cfg.PrefixLen,
			},
		}
		if err := s.AddProtocolAddress(nicID, addr, stack.AddressProperties{}); err != nil {
			return nil, fmt.Errorf("AddProtocolAddress(%s): %s", ip, err)
		}
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicID}})

	tcpFwd := tcp.NewForwarder(s, 0, 1024, ns.handleTCP)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
	udpFwd := udp.NewForwarder(s, ns.handleUDP)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	return ns, nil
}

// pumpOutbound copies frames from the netstack to the guest until ctx ends.
func (ns *netstack) pumpOutbound(fio FrameIO) {
	for {
		pkt := ns.ep.ReadContext(ns.ctx)
		if pkt == nil {
			return
		}
		v := pkt.ToView()
		frame := append([]byte(nil), v.AsSlice()...)
		v.Release()
		pkt.DecRef()
		if err := fio.WriteFrame(frame); err != nil {
			return
		}
	}
}

// inject delivers one guest frame into the netstack.
func (ns *netstack) inject(frame []byte) {
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(frame),
	})
	// Protocol number is ignored: the ethernet link wrapper re-parses
	// the frame header and dispatches by EtherType.
	ns.ep.InjectInbound(0, pkt)
	pkt.DecRef()
}

func (ns *netstack) close() {
	ns.s.Close()
	ns.s.Wait()
}
