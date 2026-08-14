package slirpstack

import (
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const udpIdleTimeout = 60 * time.Second

func addrOf(a tcpip.Address) netip.Addr {
	return netip.AddrFrom4(a.As4())
}

// flowEnds names the two ends of a guest flow. In netstack's endpoint ID
// the "remote" side is the guest (it opened the connection) and the
// "local" side is the address it dialled.
func flowEnds(id stack.TransportEndpointID) (src, dst netip.AddrPort) {
	return netip.AddrPortFrom(addrOf(id.RemoteAddress), id.RemotePort),
		netip.AddrPortFrom(addrOf(id.LocalAddress), id.LocalPort)
}

// handleTCP terminates a guest TCP connection and proxies it to the real
// destination over a host socket.
func (ns *netstack) handleTCP(r *tcp.ForwarderRequest) {
	src, dst := flowEnds(r.ID())
	if !ns.cfg.allowDest(dst.Addr()) {
		ns.cfg.Logf("tcp deny  %s -> %s", src, dst)
		r.Complete(true) // RST
		return
	}
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		r.Complete(true)
		return
	}
	r.Complete(false)
	guest := gonet.NewTCPConn(&wq, ep)
	go ns.proxyTCP(guest, src, dst)
}

// closeWrite propagates one direction's FIN: the peer sees EOF but can
// keep sending. Both gonet.TCPConn and net.TCPConn implement CloseWrite;
// anything else falls back to a full close.
func closeWrite(c net.Conn) {
	if hc, ok := c.(interface{ CloseWrite() error }); ok {
		hc.CloseWrite()
		return
	}
	c.Close()
}

func (ns *netstack) proxyTCP(guest net.Conn, src, dst netip.AddrPort) {
	defer guest.Close()
	host, err := ns.cfg.DialContext(ns.ctx, "tcp", dst.String())
	if err != nil {
		ns.cfg.Logf("tcp fail  %s -> %s: %v", src, dst, err)
		return
	}
	defer host.Close()
	ns.flowf("tcp open  %s -> %s", src, dst)

	// Counters are read by the deferred close line while the copies may
	// still be unwinding, so they have to be atomic.
	var sent, recv atomic.Int64
	start := time.Now()
	defer func() {
		ns.flowf("tcp close %s -> %s (%s, -> %s, <- %s)", src, dst,
			formatDur(time.Since(start)),
			formatBytes(sent.Load()), formatBytes(recv.Load()))
	}()

	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn, n *atomic.Int64) {
		// Count inside the copy, not from its return value: a flow torn
		// down by ctx cancellation must still report what it moved.
		io.Copy(countingWriter{dst, n}, src)
		closeWrite(dst)
		done <- struct{}{}
	}
	go cp(host, guest, &sent)
	go cp(guest, host, &recv)
	// A guest that shuts down its write side (e.g. an HTTP client after
	// the request) must still receive the response, so wait for both
	// directions, not just the first EOF.
	for range 2 {
		select {
		case <-done:
		case <-ns.ctx.Done():
			return
		}
	}
}

// handleUDP proxies one guest UDP flow. Queries to DNSIP:53 are redirected
// to the configured upstream resolver; everything else goes to the guest's
// real destination.
func (ns *netstack) handleUDP(r *udp.ForwarderRequest) bool {
	src, dst := flowEnds(r.ID())
	// note distinguishes the virtual resolver from a plain UDP flow: the
	// guest dialled 10.0.2.3:53 but the packets go to the real upstream.
	var target, note string
	if dst.Addr() == ns.cfg.DNSIP && dst.Port() == 53 {
		target = ns.cfg.UpstreamDNS
		note = " (dns via " + target + ")"
	} else {
		if !ns.cfg.allowDest(dst.Addr()) {
			ns.cfg.Logf("udp deny  %s -> %s", src, dst)
			return false // stack replies with ICMP port unreachable
		}
		target = dst.String()
	}
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		return true
	}
	guest := gonet.NewUDPConn(&wq, ep)
	go ns.proxyUDP(guest, src, dst, target, note)
	return true
}

func (ns *netstack) proxyUDP(guest net.Conn, src, dst netip.AddrPort, target, note string) {
	defer guest.Close()
	host, err := ns.cfg.DialContext(ns.ctx, "udp", target)
	if err != nil {
		ns.cfg.Logf("udp fail  %s -> %s: %v", src, dst, err)
		return
	}
	defer host.Close()
	ns.flowf("udp open  %s -> %s%s", src, dst, note)

	var sent, recv atomic.Int64
	start := time.Now()
	defer func() {
		ns.flowf("udp close %s -> %s (%s, -> %s, <- %s)", src, dst,
			formatDur(time.Since(start)),
			formatBytes(sent.Load()), formatBytes(recv.Load()))
	}()

	cp := func(dst, src net.Conn, n *atomic.Int64) {
		buf := make([]byte, frameMTU)
		for {
			src.SetReadDeadline(time.Now().Add(udpIdleTimeout))
			r, err := src.Read(buf)
			if err != nil {
				return
			}
			w, err := dst.Write(buf[:r])
			n.Add(int64(w))
			if err != nil {
				return
			}
		}
	}
	done := make(chan struct{}, 2)
	go func() { cp(host, guest, &sent); done <- struct{}{} }()
	go func() { cp(guest, host, &recv); done <- struct{}{} }()
	select {
	case <-done:
	case <-ns.ctx.Done():
	}
}
