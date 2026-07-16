package main

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

type blockedSource struct {
	addr   string
	until  time.Time
	reason string
}

// dashboard redraws the terminal in place every tick with the current
// counters and active blocklist, for the booth screen.
type dashboard struct {
	mu            sync.Mutex
	rateThreshold uint
	blockTTL      time.Duration
	target        string
	nic           string
	blocked       map[string]blockedSource
	totalBlocks   uint64
	prev          [4]uint64
	started       time.Time
}

func newDashboard(rate uint, blockTTL time.Duration) *dashboard {
	return &dashboard{
		rateThreshold: rate,
		blockTTL:      blockTTL,
		blocked:       make(map[string]blockedSource),
		started:       time.Now(),
	}
}

func (d *dashboard) setTarget(target, nic string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.target = target
	d.nic = nic
}

func (d *dashboard) block(addr string, ttl time.Duration, reason string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, exists := d.blocked[addr]; !exists {
		d.totalBlocks++
	}
	d.blocked[addr] = blockedSource{addr: addr, until: time.Now().Add(ttl), reason: reason}
}

func (d *dashboard) clear() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.blocked = make(map[string]blockedSource)
}

// expired returns addresses whose TTL has passed and removes them from the
// dashboard's view; the caller is responsible for evicting them from the
// eBPF blocklist map too.
func (d *dashboard) expired() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []string
	now := time.Now()
	for addr, b := range d.blocked {
		if now.After(b.until) {
			out = append(out, addr)
			delete(d.blocked, addr)
		}
	}
	return out
}

func bar(perSec uint64, width int) string {
	const unitsPerChar = 15
	n := int(perSec / unitsPerChar)
	if perSec > 0 && n == 0 {
		n = 1
	}
	if n > width {
		n = width
	}
	return strings.Repeat("#", n) + strings.Repeat(".", width-n)
}

func (d *dashboard) render(totals [4]uint64, interval time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()

	var deltas [4]uint64
	for i := range totals {
		if totals[i] >= d.prev[i] {
			deltas[i] = totals[i] - d.prev[i]
		}
	}
	d.prev = totals
	secs := interval.Seconds()
	rate := func(i int) uint64 {
		if secs <= 0 {
			return 0
		}
		return uint64(float64(deltas[i]) / secs)
	}

	var b strings.Builder
	b.WriteString("\x1b[2J\x1b[H") // clear screen, move cursor home
	b.WriteString("=== eBPF DDoS Guard =====================================\n")
	fmt.Fprintf(&b, " target: %-22s nic: %-10s uptime: %s\n", orDash(d.target), orDash(d.nic), time.Since(d.started).Round(time.Second))
	fmt.Fprintf(&b, " rate threshold: %d pps/source   block ttl: %s\n", d.rateThreshold, d.blockTTL)
	b.WriteString("----------------------------------------------------------\n")
	fmt.Fprintf(&b, " total     %6d pps  [%s]\n", rate(0), bar(rate(0), 40))
	fmt.Fprintf(&b, " passed    %6d pps  [%s]\n", rate(1), bar(rate(1), 40))
	fmt.Fprintf(&b, " dropped-rate      %6d pps  [%s]\n", rate(2), bar(rate(2), 40))
	fmt.Fprintf(&b, " dropped-protocol  %6d pps  [%s]\n", rate(3), bar(rate(3), 40))
	b.WriteString("----------------------------------------------------------\n")
	fmt.Fprintf(&b, " active blocklist (%d entries, %d total since start)\n", len(d.blocked), d.totalBlocks)

	addrs := make([]string, 0, len(d.blocked))
	for a := range d.blocked {
		addrs = append(addrs, a)
	}
	sort.Strings(addrs)
	now := time.Now()
	for i, a := range addrs {
		if i >= 10 {
			fmt.Fprintf(&b, "   ... and %d more\n", len(addrs)-10)
			break
		}
		bs := d.blocked[a]
		fmt.Fprintf(&b, "   %-22s remaining=%-5s reason=%s\n", a, bs.until.Sub(now).Round(time.Second), bs.reason)
	}
	b.WriteString("==========================================================\n")

	fmt.Print(b.String())
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
