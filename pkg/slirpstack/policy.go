package slirpstack

import (
	"bufio"
	"net"
	"net/netip"
	"os"
	"strings"
)

// allowDest is the egress policy: with AllowPrivate unset, only public
// unicast IPv4 destinations may leave the relay. This is what keeps a
// reachable wsslirpd from becoming an open proxy into its own network.
func (c Config) allowDest(a netip.Addr) bool {
	if c.AllowPrivate {
		return true
	}
	if !a.Is4() {
		return false
	}
	switch {
	case a.IsLoopback(), a.IsPrivate(), a.IsLinkLocalUnicast(),
		a.IsLinkLocalMulticast(), a.IsMulticast(), a.IsUnspecified():
		return false
	}
	return true
}

// defaultUpstreamDNS picks the host's first resolv.conf nameserver,
// falling back to a public resolver.
func defaultUpstreamDNS() string {
	f, err := os.Open("/etc/resolv.conf")
	if err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) >= 2 && fields[0] == "nameserver" {
				if ip, err := netip.ParseAddr(fields[1]); err == nil && ip.Is4() {
					return net.JoinHostPort(ip.String(), "53")
				}
			}
		}
	}
	return "1.1.1.1:53"
}
