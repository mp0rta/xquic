// Minimal CONNECT-IP test proxy using quic-go/connect-ip-go.
// Usage: go run main.go [-addr :4443] [-cert server.crt] [-key server.key]
//
// Accepts CONNECT-IP requests, assigns 10.0.0.2/32 to the client,
// advertises a default route, and logs received IP packets.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

func main() {
	addr := flag.String("addr", ":4443", "listen address")
	certFile := flag.String("cert", "server.crt", "TLS certificate file")
	keyFile := flag.String("key", "server.key", "TLS key file")
	host := flag.String("host", "localhost:4443", "expected :authority host:port (must match client SNI)")
	flag.Parse()

	// URI template for CONNECT-IP.
	// connect-ip-go does not support IP flow forwarding (templates with variables),
	// so use a static path. The host must match the client's :authority header.
	tmpl := uritemplate.MustNew("https://" + *host + "/ip")

	var proxy connectip.Proxy

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Request: %s %s %s (protocol: %s)",
			r.Method, r.URL.Path, r.Proto, r.Header.Get(":protocol"))

		req, err := connectip.ParseRequest(r, tmpl)
		if err != nil {
			var perr *connectip.RequestParseError
			if errors.As(err, &perr) {
				log.Printf("Parse error (HTTP %d): %v", perr.HTTPStatus, err)
				w.WriteHeader(perr.HTTPStatus)
				return
			}
			log.Printf("Bad request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		log.Println("CONNECT-IP request accepted, establishing tunnel...")

		conn, err := proxy.Proxy(w, req)
		if err != nil {
			log.Printf("Proxy error: %v", err)
			return
		}
		defer conn.Close()

		log.Println("Tunnel established, assigning address...")

		// Assign 10.0.0.2/32 to the client
		clientPrefix := netip.MustParsePrefix("10.0.0.2/32")
		if err := conn.AssignAddresses(context.Background(), []netip.Prefix{clientPrefix}); err != nil {
			log.Printf("AssignAddresses error: %v", err)
			return
		}
		log.Printf("Assigned address: %s", clientPrefix)

		// Advertise a default route (0.0.0.0/0)
		defaultRoute := connectip.IPRoute{
			StartIP:    netip.MustParseAddr("0.0.0.0"),
			EndIP:      netip.MustParseAddr("255.255.255.255"),
			IPProtocol: 0, // all protocols
		}
		if err := conn.AdvertiseRoute(context.Background(), []connectip.IPRoute{defaultRoute}); err != nil {
			log.Printf("AdvertiseRoute error: %v", err)
			return
		}
		log.Println("Advertised default route")

		// Read and log IP packets
		buf := make([]byte, 65536)
		for {
			n, err := conn.ReadPacket(buf)
			if err != nil {
				var closeErr *connectip.CloseError
				if errors.As(err, &closeErr) {
					log.Println("Connection closed")
				} else {
					log.Printf("ReadPacket error: %v", err)
				}
				return
			}

			pkt := buf[:n]
			if len(pkt) > 0 {
				version := pkt[0] >> 4
				log.Printf("Received IP packet: version=%d, len=%d, hex=%x",
					version, n, pkt[:min(n, 40)])
			}

			// Echo the packet back (for testing)
			if _, err := conn.WritePacket(pkt); err != nil {
				log.Printf("WritePacket error: %v", err)
				return
			}
			log.Printf("Echoed %d bytes back", n)
		}
	})

	// Load TLS certificate
	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("Failed to load TLS certificate: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h3"},
	}

	// Create QUIC listener
	udpAddr, err := net.ResolveUDPAddr("udp", *addr)
	if err != nil {
		log.Fatalf("Failed to resolve address: %v", err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	quicConf := &quic.Config{
		EnableDatagrams: true,
	}

	listener, err := quic.ListenEarly(udpConn, tlsConfig, quicConf)
	if err != nil {
		log.Fatalf("Failed to create QUIC listener: %v", err)
	}

	server := &http3.Server{
		Handler:         mux,
		EnableDatagrams: true,
	}

	fmt.Printf("CONNECT-IP proxy listening on %s\n", *addr)
	if err := server.ServeListener(listener); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
