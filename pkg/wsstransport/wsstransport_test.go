package wsstransport_test

import (
	"context"
	"io"
	"net"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/yoshiharu-ishii/wsslirp/internal/testutil"
	"github.com/yoshiharu-ishii/wsslirp/pkg/slirpstack"
	"github.com/yoshiharu-ishii/wsslirp/pkg/wsstransport"
)

// TestEndToEndOverWebSocket is the full PoC path: a netstack guest speaks
// Ethernet frames over a real WebSocket to the handler, which NATs a TCP
// connection out to a local echo server.
func TestEndToEndOverWebSocket(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()

	h := &wsstransport.Handler{
		Config: slirpstack.Config{
			Logf: t.Logf,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("tcp", echo.Addr().String())
			},
		},
		Token: "sekrit",
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	wsURL := strings.Replace(srv.URL, "http://", "ws://", 1)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	c, _, err := websocket.Dial(ctx, wsURL+"/?token=sekrit", nil)
	if err != nil {
		t.Fatalf("websocket dial: %v", err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")
	c.SetReadLimit(1 << 16)

	g, err := testutil.NewGuest(ctx, wsstransport.NewConnFrameIO(ctx, c))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(g.Close)

	conn, err := g.DialTCP(ctx, netip.MustParseAddrPort("192.0.2.10:80"))
	if err != nil {
		t.Fatalf("guest dial through websocket: %v", err)
	}
	defer conn.Close()
	msg := []byte("frames over websocket")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("echo read: %v", err)
	}
	if string(got) != string(msg) {
		t.Fatalf("echo = %q, want %q", got, msg)
	}
}

func TestTokenRequired(t *testing.T) {
	h := &wsstransport.Handler{Token: "sekrit"}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	wsURL := strings.Replace(srv.URL, "http://", "ws://", 1)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if c, _, err := websocket.Dial(ctx, wsURL+"/?token=wrong", nil); err == nil {
		c.Close(websocket.StatusNormalClosure, "")
		t.Fatal("handshake with wrong token succeeded")
	}
	if c, _, err := websocket.Dial(ctx, wsURL, nil); err == nil {
		c.Close(websocket.StatusNormalClosure, "")
		t.Fatal("handshake without token succeeded")
	}
}
