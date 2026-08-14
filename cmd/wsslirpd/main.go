// wsslirpd is a user-mode NAT daemon for Ethernet-frame guests.
// Browsers connect over wss:// (put a TLS terminator in front), native
// emulators over ws://localhost. One process serves many guests, each in
// its own isolated 10.0.2.0/24.
package main

import (
	"flag"
	"log"
	"net/http"
	"os"

	"github.com/yoshiharu-ishii/wsslirp/pkg/slirpstack"
	"github.com/yoshiharu-ishii/wsslirp/pkg/wsstransport"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8087", "listen address")
	token := flag.String("token", os.Getenv("WSSLIRP_TOKEN"), "shared token required as ?token= (empty disables auth)")
	allowPrivate := flag.Bool("allow-private", false, "allow egress to loopback/private destinations (dev only)")
	upstreamDNS := flag.String("upstream-dns", "", "upstream resolver as host:port (default: resolv.conf, else 1.1.1.1:53)")
	logFlows := flag.Bool("log-flows", true, "log one audit line per flow (open/close, bytes per direction)")
	flag.Parse()

	h := &wsstransport.Handler{
		Config: slirpstack.Config{
			AllowPrivate: *allowPrivate,
			UpstreamDNS:  *upstreamDNS,
			LogFlows:     *logFlows,
			Logf:         slirpstack.Logger("slirp: "),
		},
		Token: *token,
	}
	mux := http.NewServeMux()
	mux.Handle("/net", h)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok\n"))
	})

	if *token == "" {
		log.Printf("warning: no token set; anyone who can reach %s can use this relay", *listen)
	}
	if *allowPrivate {
		log.Printf("warning: -allow-private is on; guests can reach private networks")
	}
	log.Printf("wsslirpd listening on %s (endpoint /net)", *listen)
	log.Fatal(http.ListenAndServe(*listen, mux))
}
