// Package wsstransport serves slirpstack guests over WebSocket.
// Protocol: one binary WebSocket message = one Ethernet frame. That is
// the entire contract; TLS termination is left to the deployment.
package wsstransport

import (
	"context"
	"crypto/subtle"
	"net/http"

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
	logf := h.Config.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	logf("guest connected: %s", r.RemoteAddr)
	err = slirpstack.Run(r.Context(), NewConnFrameIO(r.Context(), c), h.Config)
	logf("guest disconnected: %s (%v)", r.RemoteAddr, err)
	c.Close(websocket.StatusNormalClosure, "")
}

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
