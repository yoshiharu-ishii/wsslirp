// Package wsstransport serves slirpstack guests over WebSocket.
// Protocol: one binary WebSocket message = one Ethernet frame. That is
// the entire contract; TLS termination is left to the deployment.
package wsstransport

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/yoshiharu-ishii/wsslirp/pkg/slirpstack"
)

// Handler upgrades HTTP requests to WebSocket and runs one isolated
// slirpstack per connection.
type Handler struct {
	Config slirpstack.Config

	// Token, when non-empty, must match the ?token= query parameter.
	Token string
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.Token != "" {
		got := r.URL.Query().Get("token")
		if subtle.ConstantTimeCompare([]byte(got), []byte(h.Token)) != 1 {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
	}
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns: []string{"*"},
	})
	if err != nil {
		return
	}
	c.SetReadLimit(1 << 16)

	// Every line this guest produces carries its id, so flows can be
	// attributed when many guests share one daemon. The id is only
	// tied to a real client by the connect line below.
	cfg := h.Config
	id := fmt.Sprintf("g%d", guestSeq.Add(1))
	logf := func(string, ...any) {}
	if h.Config.Logf != nil {
		parent := h.Config.Logf
		logf = func(format string, args ...any) {
			parent("["+id+"] "+format, args...)
		}
	}
	cfg.Logf = logf

	logf("guest connected from %s", r.RemoteAddr)
	start := time.Now()
	err = slirpstack.Run(r.Context(), NewConnFrameIO(r.Context(), c), cfg)
	logf("guest disconnected after %s (%v)", time.Since(start).Round(time.Millisecond), err)
	c.Close(websocket.StatusNormalClosure, "")
}

// guestSeq numbers guests within one daemon lifetime.
var guestSeq atomic.Uint64

type wsFrameIO struct {
	ctx context.Context
	c   *websocket.Conn
}

// NewConnFrameIO adapts a WebSocket connection to slirpstack.FrameIO.
// It is used by the server and by native Go clients (e.g. tests).
func NewConnFrameIO(ctx context.Context, c *websocket.Conn) slirpstack.FrameIO {
	return &wsFrameIO{ctx: ctx, c: c}
}

func (f *wsFrameIO) ReadFrame() ([]byte, error) {
	for {
		typ, data, err := f.c.Read(f.ctx)
		if err != nil {
			return nil, err
		}
		if typ == websocket.MessageBinary {
			return data, nil
		}
	}
}

func (f *wsFrameIO) WriteFrame(frame []byte) error {
	return f.c.Write(f.ctx, websocket.MessageBinary, frame)
}
