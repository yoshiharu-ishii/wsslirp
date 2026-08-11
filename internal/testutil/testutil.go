// Package testutil provides an in-memory frame pipe and a netstack-backed
// synthetic guest for end-to-end tests. The guest speaks real Ethernet:
// it ARPs for the gateway, opens real TCP handshakes, and so exercises the
// exact frame path a rustx86 guest OS would.
package testutil

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"github.com/yoshiharu-ishii/wsslirp/pkg/slirpstack"
)

type pipeEnd struct {
	rx   <-chan []byte
	tx   chan<- []byte
	done <-chan struct{}
}

func (p *pipeEnd) ReadFrame() ([]byte, error) {
	select {
	case f := <-p.rx:
		return f, nil
	case <-p.done:
		return nil, io.EOF
	}
}

func (p *pipeEnd) WriteFrame(f []byte) error {
	cp := append([]byte(nil), f...)
	select {
	case p.tx <- cp:
		return nil
	case <-p.done:
		return io.EOF
	}
}

// FramePipe returns two connected FrameIO ends. Frames written to one end
// are read from the other. Both ends fail once ctx is done.
func FramePipe(ctx context.Context) (a, b slirpstack.FrameIO) {
	ab := make(chan []byte, 512)
	ba := make(chan []byte, 512)
	return &pipeEnd{rx: ba, tx: ab, done: ctx.Done()},
		&pipeEnd{rx: ab, tx: ba, done: ctx.Done()}
}

// Guest is a synthetic guest with a static slirp-style address, driving
// real TCP/UDP through an Ethernet FrameIO.
type Guest struct {
	Stack *stack.Stack
	ep    *channel.Endpoint
}

// NewGuest builds a guest stack (10.0.2.15/24, default route via
// 10.0.2.2) and starts pumping frames over fio until ctx ends.
func NewGuest(ctx context.Context, fio slirpstack.FrameIO) (*Guest, error) {
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
	guestMAC := tcpip.LinkAddress("\x52\x55\x0a\x00\x02\x0f")
	ep := channel.New(512, 1514, guestMAC)
	if err := s.CreateNIC(1, ethernet.New(ep)); err != nil {
		return nil, fmt.Errorf("guest CreateNIC: %s", err)
	}
	addr := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4([4]byte{10, 0, 2, 15}),
			PrefixLen: 24,
		},
	}
	if err := s.AddProtocolAddress(1, addr, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("guest AddProtocolAddress: %s", err)
	}
	s.SetRouteTable([]tcpip.Route{{
		Destination: header.IPv4EmptySubnet,
		Gateway:     tcpip.AddrFrom4([4]byte{10, 0, 2, 2}),
		NIC:         1,
	}})

	go func() {
		for {
			pkt := ep.ReadContext(ctx)
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
	}()
	go func() {
		for {
			frame, err := fio.ReadFrame()
			if err != nil {
				return
			}
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(frame),
			})
			ep.InjectInbound(0, pkt)
			pkt.DecRef()
		}
	}()
	return &Guest{Stack: s, ep: ep}, nil
}

// DialTCP opens a TCP connection from the guest to addr through the slirp.
func (g *Guest) DialTCP(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	full := tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFrom4(addr.Addr().As4()),
		Port: addr.Port(),
	}
	return gonet.DialContextTCP(ctx, g.Stack, full, ipv4.ProtocolNumber)
}

// DialUDP opens a connected UDP flow from the guest to addr.
func (g *Guest) DialUDP(addr netip.AddrPort) (net.Conn, error) {
	full := tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFrom4(addr.Addr().As4()),
		Port: addr.Port(),
	}
	return gonet.DialUDP(g.Stack, nil, &full, ipv4.ProtocolNumber)
}

// Close tears down the guest stack.
func (g *Guest) Close() {
	g.Stack.Close()
	g.Stack.Wait()
}
