// Package slirpstack is a transport-agnostic user-mode NAT ("slirp") for
// guests that emit raw Ethernet frames. It terminates the guest's TCP/UDP
// inside a gVisor netstack and re-dials real sockets on the host side.
//
// The only contract with the outside world is FrameIO: one call, one
// Ethernet frame. Anything that can carry frames (WebSocket, Unix socket,
// in-process channel) can be a transport.
package slirpstack

import (
	"context"
	"log"
	"net"
	"net/netip"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// FrameIO carries Ethernet frames between a guest and the slirp stack.
// ReadFrame blocks until a frame arrives or the transport fails.
// WriteFrame must be safe for concurrent use.
type FrameIO interface {
	ReadFrame() ([]byte, error)
	WriteFrame([]byte) error
}

// Config describes one guest network. The zero value is completed by
// withDefaults with the classic slirp layout (10.0.2.0/24).
type Config struct {
	GatewayIP  netip.Addr // stack-owned gateway address (default 10.0.2.2)
	DNSIP      netip.Addr // stack-owned DNS address (default 10.0.2.3)
	GuestIP    netip.Addr // address leased to the guest via DHCP (default 10.0.2.15)
	PrefixLen  int        // subnet prefix length (default 24)
	GatewayMAC net.HardwareAddr

	// UpstreamDNS is where queries sent to DNSIP:53 are forwarded,
	// as host:port. Default: first nameserver in /etc/resolv.conf,
	// falling back to 1.1.1.1:53.
	UpstreamDNS string

	// AllowPrivate permits egress to loopback/private/link-local
	// destinations. Keep false on anything reachable from the internet;
	// it is the SSRF/open-proxy guard.
	AllowPrivate bool

	// DialContext opens outbound host connections ("tcp"/"udp").
	// Defaults to a net.Dialer with a 10s timeout. Tests override this.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)

	// Ping sends one ICMP echo carrying data to dst and returns the
	// reply payload. seq is the guest's sequence number. Defaults to an
	// unprivileged ping socket. Tests override this.
	Ping func(ctx context.Context, dst netip.Addr, seq int, data []byte) ([]byte, error)

	// LogFlows emits one audit line per flow (open and close, with byte
	// counts per direction). Off by default: together the lines are a
	// complete record of everywhere the guest went. Denials and errors
	// are logged regardless.
	LogFlows bool

	Logf func(format string, args ...any)
}

func (c Config) withDefaults() Config {
	if !c.GatewayIP.IsValid() {
		c.GatewayIP = netip.AddrFrom4([4]byte{10, 0, 2, 2})
	}
	if !c.DNSIP.IsValid() {
		c.DNSIP = netip.AddrFrom4([4]byte{10, 0, 2, 3})
	}
	if !c.GuestIP.IsValid() {
		c.GuestIP = netip.AddrFrom4([4]byte{10, 0, 2, 15})
	}
	if c.PrefixLen == 0 {
		c.PrefixLen = 24
	}
	if c.GatewayMAC == nil {
		c.GatewayMAC = net.HardwareAddr{0x52, 0x55, 0x0a, 0x00, 0x02, 0x02}
	}
	if c.UpstreamDNS == "" {
		c.UpstreamDNS = defaultUpstreamDNS()
	}
	if c.DialContext == nil {
		d := &net.Dialer{Timeout: 10 * time.Second}
		c.DialContext = d.DialContext
	}
	if c.Ping == nil {
		c.Ping = systemPing
	}
	if c.Logf == nil {
		c.Logf = func(string, ...any) {}
	}
	return c
}

// Run serves one guest over fio until ctx is canceled or the transport
// fails. Each call owns an isolated network stack, so guests never see
// each other.
func Run(ctx context.Context, fio FrameIO, cfg Config) error {
	cfg = cfg.withDefaults()
	ns, err := newNetstack(ctx, cfg)
	if err != nil {
		return err
	}
	defer ns.close()

	go ns.pumpOutbound(fio)

	for {
		frame, err := fio.ReadFrame()
		if err != nil {
			return err
		}
		ns.dispatch(frame, fio)
	}
}

// dispatchOpts decodes lazily (layers are parsed only when a handler
// asks for them) and without copying (the parsed layers point into
// frame). Nothing parsed here may outlive dispatch: the ICMP path
// snapshots what it needs before going async, and inject copies the
// frame into netstack's own storage.
var dispatchOpts = gopacket.DecodeOptions{Lazy: true, NoCopy: true}

// dispatch classifies one guest frame. The three checks share a single
// parse — each one used to build its own packet, which cost more than
// the work they were deciding about.
func (ns *netstack) dispatch(frame []byte, fio FrameIO) {
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, dispatchOpts)
	if ns.maybeHandleDHCP(pkt, fio) {
		return
	}
	if ns.maybeHandleICMP(pkt, fio) {
		return
	}
	if ns.isArpForGuest(pkt) {
		// ゲスト自身のIPへのARPには誰も答えてはいけない。
		// netstackはspoofing有効で何にでも代返するので、ここで落とす。
		// mTCPは起動時にこのARPでアドレス衝突を検査していて、
		// 代返すると「他のマシンが10.0.2.15を使っている」と誤検出する
		return
	}
	ns.inject(frame)
}

// Logger returns a Logf writing through the standard logger with a prefix.
func Logger(prefix string) func(string, ...any) {
	return func(format string, args ...any) {
		log.Printf(prefix+format, args...)
	}
}
