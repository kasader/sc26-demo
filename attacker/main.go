package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"time"
)

// Bitflag set, mirroring TCP's FIN/SYN/RST/PSH/ACK bit positions.
const (
	flagFIN = 0x01 // graceful close, like TCP FIN
	flagSYN = 0x02 // open connection, like TCP SYN
	flagRST = 0x04 // abort connection, like TCP RST
	flagDAT = 0x08 // payload present, like TCP PSH
	flagACK = 0x10 // acknowledgment, like TCP ACK

	flagGarbage = 0xff
)

// Set of real protocols send flags in combination.
var flagCombos = []byte{
	flagSYN,
	flagSYN | flagACK,
	flagDAT | flagACK,
	flagACK,
	flagFIN | flagACK,
}

// Each mode tells a different part of the demo story:
//   - legit:   a handful of real players, always under any reasonable rate limit.
//   - garbage: a couple of sources sending malformed payloads, but slowly enough
//     to never trip a per-source rate limiter -- only protocol validation catches this.
//   - flood:   a couple of sources sending as fast as possible -- trips the rate limiter.
//   - evasive: many distinct sources (ephemeral ports), each individually under the
//     rate limit, only caught in aggregate by protocol validation. Simulates an
//     attacker adapting to avoid per-source rate limiting.
type modeConfig struct {
	workers int
	pps     int
	garbage bool
}

var modes = map[string]modeConfig{
	"legit":   {workers: 3, pps: 2, garbage: false},
	"garbage": {workers: 2, pps: 10, garbage: true},
	"flood":   {workers: 2, pps: 150, garbage: true},
	"evasive": {workers: 50, pps: 5, garbage: true},
}

func main() {
	var (
		target   string
		mode     string
		workers  int
		pps      int
		duration time.Duration
	)
	flag.StringVar(&target, "target", "", "Victim address, e.g. 10.10.0.2:9999")
	flag.StringVar(&mode, "mode", "legit", "legit | garbage | flood | evasive")
	flag.IntVar(&workers, "workers", 0, "Override the mode's default number of sources (0 = mode default).")
	flag.IntVar(&pps, "pps", 0, "Override the mode's default packets/sec per source (0 = mode default).")
	flag.DurationVar(&duration, "duration", 0, "Stop automatically after this long (0 = run until Ctrl+C).")
	flag.Parse()

	if target == "" {
		log.Fatal("missing -target")
	}
	cfg, ok := modes[mode]
	if !ok {
		log.Fatalf("unknown -mode %q (want legit, garbage, flood, or evasive)", mode)
	}
	if workers > 0 {
		cfg.workers = workers
	}
	if pps > 0 {
		cfg.pps = pps
	}

	targetAddr, err := net.ResolveUDPAddr("udp4", target)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("mode=%s sources=%d pps/source=%d target=%s", mode, cfg.workers, cfg.pps, target)

	var sent atomic.Uint64
	stop := make(chan struct{})

	var wg sync.WaitGroup
	for i := 0; i < cfg.workers; i++ {
		wg.Go(func() {
			// Binding each worker to its own ephemeral port gives it a distinct
			// source (address_key = ip+port) from the guard's PoV.
			conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
			if err != nil {
				log.Printf("worker: %v", err)
				return
			}
			defer conn.Close()

			ticker := time.NewTicker(time.Second / time.Duration(cfg.pps))
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					if _, err := conn.WriteToUDP(makePayload(cfg.garbage), targetAddr); err == nil {
						sent.Add(1)
					}
				case <-stop:
					return
				}
			}
		})
	}

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt)

	var timeoutC <-chan time.Time
	if duration > 0 {
		timeoutC = time.After(duration)
	}

	statTicker := time.NewTicker(time.Second)
	defer statTicker.Stop()
	var last uint64
loop:
	for {
		select {
		case <-statTicker.C:
			now := sent.Load()
			fmt.Printf("sent %d pkt/s (total %d)\n", now-last, now)
			last = now
		case <-timeoutC:
			break loop
		case <-sigc:
			break loop
		}
	}
	close(stop)
	wg.Wait()
	log.Printf("stopped, total sent=%d", sent.Load())
}

func makePayload(garbage bool) []byte {
	buf := make([]byte, 32)
	for i := range buf {
		buf[i] = byte(i)
	}
	if garbage {
		buf[3] = flagGarbage
	} else {
		buf[3] = flagCombos[rand.IntN(len(flagCombos))]
	}
	return buf
}
