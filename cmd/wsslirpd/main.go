// wsslirpd is a user-mode NAT daemon for Ethernet-frame guests.
// Browsers connect over wss:// (put a TLS terminator in front), native
// emulators over ws://localhost. One process serves many guests, each in
// its own isolated 10.0.2.0/24.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime/debug"

	"github.com/yoshiharu-ishii/wsslirp/pkg/slirpstack"
	"github.com/yoshiharu-ishii/wsslirp/pkg/wsstransport"
)

// version is stamped by the release build:
// -ldflags "-X main.version=v0.1.0". Unstamped builds fall back to the
// VCS revision the toolchain records.
var version = ""

func buildVersion() string {
	if version != "" {
		return version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	rev, dirty := "", ""
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			if len(s.Value) > 7 {
				rev = s.Value[:7]
			} else {
				rev = s.Value
			}
		case "vcs.modified":
			if s.Value == "true" {
				dirty = "-dirty"
			}
		}
	}
	if rev == "" {
		return "dev"
	}
	return "dev-" + rev + dirty
}

func main() {
	listen := flag.String("listen", "127.0.0.1:8087", "listen address")
	token := flag.String("token", os.Getenv("WSSLIRP_TOKEN"), "shared token required as ?token= (empty disables auth)")
	allowPrivate := flag.Bool("allow-private", false, "allow egress to loopback/private destinations (dev only)")
	upstreamDNS := flag.String("upstream-dns", "", "upstream resolver as host:port (default: resolv.conf, else 1.1.1.1:53)")
	logFlows := flag.Bool("log-flows", true, "log one audit line per flow (open/close, bytes per direction)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("wsslirpd", buildVersion())
		return
	}

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
	// The version goes in the startup line on purpose: a forgotten
	// daemon from an earlier build listening on the same port looks
	// exactly like a bug in the new one.
	log.Printf("wsslirpd %s listening on %s (endpoint /net)", buildVersion(), *listen)
	log.Fatal(http.ListenAndServe(*listen, mux))
}
