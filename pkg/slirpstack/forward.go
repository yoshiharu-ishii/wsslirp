package slirpstack

import (
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const udpIdleTimeout = 60 * time.Second

func addrOf(a tcpip.Address) netip.Addr {
	return netip.AddrFrom4(a.As4())
}

// handleTCP terminates a guest TCP connection and proxies it to the real
// destination over a host socket.
func (ns *netstack) handleTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	dst := addrOf(id.LocalAddress)
	if !ns.cfg.allowDest(dst) {
		ns.cfg.Logf("tcp: denied egress to %s:%d", dst, id.LocalPort)
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
	target := net.JoinHostPort(dst.String(), strconv.Itoa(int(id.LocalPort)))
	go ns.proxyTCP(guest, target)
}

func (ns *netstack) proxyTCP(guest net.Conn, target string) {
	defer guest.Close()
	host, err := ns.cfg.DialContext(ns.ctx, "tcp", target)
	if err != nil {
		ns.cfg.Logf("tcp: dial %s: %v", target, err)
		return
	}
	defer host.Close()
	ns.cfg.Logf("tcp: %s connected", target)
	done := make(chan struct{}, 2)
	cp := func(dst io.Writer, src io.Reader) {
		io.Copy(dst, src)
		done <- struct{}{}
	}
	go cp(host, guest)
	go cp(guest, host)
	select {
	case <-done:
	case <-ns.ctx.Done():
	}
}

// handleUDP proxies one guest UDP flow. Queries to DNSIP:53 are redirected
// to the configured upstream resolver; everything else goes to the guest's
// real destination.
func (ns *netstack) handleUDP(r *udp.ForwarderRequest) bool {
	id := r.ID()
	dst := addrOf(id.LocalAddress)
	var target string
	if dst == ns.cfg.DNSIP && id.LocalPort == 53 {
		target = ns.cfg.UpstreamDNS
	} else {
		if !ns.cfg.allowDest(dst) {
			ns.cfg.Logf("udp: denied egress to %s:%d", dst, id.LocalPort)
			return false // stack replies with ICMP port unreachable
		}
		target = net.JoinHostPort(dst.String(), strconv.Itoa(int(id.LocalPort)))
	}
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		return true
	}
	guest := gonet.NewUDPConn(&wq, ep)
	go ns.proxyUDP(guest, target)
	return true
}

func (ns *netstack) proxyUDP(guest net.Conn, target string) {
	defer guest.Close()
	host, err := ns.cfg.DialContext(ns.ctx, "udp", target)
	if err != nil {
		ns.cfg.Logf("udp: dial %s: %v", target, err)
		return
	}
	defer host.Close()
	cp := func(dst, src net.Conn) {
		buf := make([]byte, frameMTU)
		for {
			src.SetReadDeadline(time.Now().Add(udpIdleTimeout))
			n, err := src.Read(buf)
			if err != nil {
				return
			}
			if _, err := dst.Write(buf[:n]); err != nil {
				return
			}
		}
	}
	done := make(chan struct{}, 2)
	go func() { cp(host, guest); done <- struct{}{} }()
	go func() { cp(guest, host); done <- struct{}{} }()
	select {
	case <-done:
	case <-ns.ctx.Done():
	}
}
