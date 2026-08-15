package main

import (
	"flag"
	"log"
	"net"
	"sync/atomic"
	"time"
)

func main() {
	var listen string
	flag.StringVar(&listen, "listen", "10.10.0.2:9999", "UDP address to receive traffic on.")
	flag.Parse()

	addr, err := net.ResolveUDPAddr("udp4", listen)
	if err != nil {
		log.Fatal(err)
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	log.Printf("victim UDP server listening on %s", listen)

	var received atomic.Uint64
	go func() {
		buf := make([]byte, 1500)
		for {
			if _, _, err := conn.ReadFromUDP(buf); err != nil {
				return
			}
			received.Add(1)
		}
	}()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var last uint64
	for range ticker.C {
		now := received.Load()
		log.Printf("received %d pkt/s (total %d) (cleared eBPF guard)", now-last, now)
		last = now
	}
}
