package slirpstack

import (
	"fmt"
	"io"
	"sync/atomic"
	"time"
)

// Flow lines are written in one fixed shape so a log can be audited by
// eye or by grep:
//
//	<proto> <event> <guest addr> -> <destination> [detail]
//
// The arrow always points the way the connection was opened, guest on
// the left. Byte counts on the close line are tagged with the direction
// they travelled: "-> 412 B" left the guest, "<- 1.4 KiB" came back.
//
// flowf emits only when Config.LogFlows is set, because these lines
// record every destination a guest reaches. Denials and errors go
// through Logf directly: they are security events, not traffic.
func (ns *netstack) flowf(format string, args ...any) {
	if ns.cfg.LogFlows {
		ns.cfg.Logf(format, args...)
	}
}

// countingWriter tallies bytes as they pass, so a flow's byte counts are
// readable even while the copy is still running.
type countingWriter struct {
	w io.Writer
	n *atomic.Int64
}

func (c countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n.Add(int64(n))
	return n, err
}

func formatBytes(n int64) string {
	switch {
	case n < 1024:
		return fmt.Sprintf("%d B", n)
	case n < 1024*1024:
		return fmt.Sprintf("%.1f KiB", float64(n)/1024)
	default:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1024*1024))
	}
}

func formatDur(d time.Duration) string {
	switch {
	case d < time.Millisecond:
		// A sub-millisecond round trip is a real measurement, not a
		// zero: keep it out of the "0s" bucket.
		return d.Round(time.Microsecond).String()
	case d < time.Second:
		return d.Round(time.Millisecond).String()
	default:
		return d.Round(100 * time.Millisecond).String()
	}
}
