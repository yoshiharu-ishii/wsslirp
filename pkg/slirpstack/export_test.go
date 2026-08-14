package slirpstack

import (
	"context"
	"net/netip"
)

// SystemPingForTest exposes the default ping implementation so
// benchmarks can measure it directly.
func SystemPingForTest() func(ctx context.Context, dst netip.Addr, seq int, data []byte) ([]byte, error) {
	return systemPing
}
