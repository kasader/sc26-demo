package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	var (
		debugMode bool
		rate      uint
		nic       string
		target    string
		blockTTL  time.Duration
	)
	flag.BoolVar(&debugMode, "debug", false, "Enable bpf_printk tracing (view via /sys/kernel/debug/tracing/trace_pipe).")
	flag.UintVar(&rate, "rate", 30, "Per-source packets/sec allowed before auto-block kicks in.")
	flag.StringVar(&nic, "nic", "", "Interface to attach the XDP guard to, e.g. veth-vic.")
	flag.StringVar(&target, "target", "", "Protected IPv4 host:port to police, e.g. 10.10.0.2:9999.")
	flag.DurationVar(&blockTTL, "block-ttl", 15*time.Second, "How long an auto-blocked source stays blocked.")
	flag.Parse()

	if nic == "" || target == "" {
		log.Fatal("both -nic and -target are required")
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	spec, err := loadGuard()
	if err != nil {
		log.Fatalf("loading CollectionSpec: %s", err)
	}

	varDebug := uint32(0)
	if debugMode {
		varDebug = 1
	}
	if err := spec.Variables["is_debug"].Set(varDebug); err != nil {
		log.Fatalf("failed to set is_debug: %v", err)
	}
	if err := spec.Variables["rate_threshold"].Set(uint32(rate)); err != nil {
		log.Fatalf("failed to set rate_threshold: %v", err)
	}

	var objs guardObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	ringReader, err := ringbuf.NewReader(objs.BlockEvents)
	if err != nil {
		log.Fatal("Opening ring buffer:", err)
	}
	defer ringReader.Close()

	dash := newDashboard(rate, blockTTL)

	// Attach the program to the NIC and tell it which target to police. These
	// used to be driven at runtime over an HTTP control API; for the booth demo
	// the target is fixed, so we just do it once at startup from flags.
	targetAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil || targetAddr.IP.To4() == nil {
		log.Fatalf("-target must be an IPv4 host:port: %v", err)
	}
	iface, err := net.InterfaceByName(nic)
	if err != nil {
		log.Fatalf("interface %q: %v", nic, err)
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.Guard,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode, // required: XDP native mode isn't supported on veth
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	defer xdpLink.Close()

	targetKey := guardAddressKey{
		Address: binary.BigEndian.Uint32(targetAddr.IP.To4()),
		Port:    uint16(targetAddr.Port),
	}
	if err := objs.Target.Update(uint32(0), targetKey, ebpf.UpdateAny); err != nil {
		log.Fatal("Setting target:", err)
	}
	dash.setTarget(target, nic)
	slog.Info("attached", "target", target, "nic", nic)

	// Ring buffer consumer: the eBPF program decides in-kernel to drop and
	// notifies here so the block can be recorded with a TTL. The drop for
	// the packet that tripped the limiter already happened before this runs.
	go func() {
		for {
			rec, err := ringReader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				continue
			}
			if len(rec.RawSample) < 12 {
				continue
			}
			addr := binary.LittleEndian.Uint32(rec.RawSample[0:4])
			port := binary.LittleEndian.Uint16(rec.RawSample[4:6])
			pps := binary.LittleEndian.Uint32(rec.RawSample[8:12])

			key := guardAddressKey{Address: addr, Port: port}
			if err := objs.Blocklist.Put(key, uint8(1)); err != nil {
				continue
			}
			addrStr := fmt.Sprintf("%s:%d", ipString(addr), port)
			dash.block(addrStr, blockTTL, fmt.Sprintf("auto (%d pps)", pps))
			slog.Info("auto-blocked", "address", addrStr, "pps", pps)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	gcTicker := time.NewTicker(time.Second)
	defer gcTicker.Stop()

	for {
		select {
		case <-ticker.C:
			var totals [4]uint64
			for i := range totals {
				v, err := sumPercpu(objs.PktStats, uint32(i))
				if err != nil {
					continue
				}
				totals[i] = v
			}
			dash.render(totals, 500*time.Millisecond)

		case <-gcTicker.C:
			for _, addrStr := range dash.expired() {
				host, portStr, err := net.SplitHostPort(addrStr)
				if err != nil {
					continue
				}
				ip := net.ParseIP(host).To4()
				if ip == nil {
					continue
				}
				var port int
				fmt.Sscanf(portStr, "%d", &port)
				key := guardAddressKey{
					Address: binary.BigEndian.Uint32(ip),
					Port:    uint16(port),
				}
				_ = objs.Blocklist.Delete(key)
			}

		case <-stop:
			log.Print("Received signal, exiting..")
			return
		}
	}
}

func sumPercpu(m *ebpf.Map, key uint32) (uint64, error) {
	values := make([]uint64, ebpf.MustPossibleCPU())
	if err := m.Lookup(key, &values); err != nil {
		return 0, err
	}
	var total uint64
	for _, v := range values {
		total += v
	}
	return total, nil
}

func ipString(addr uint32) string {
	return net.IPv4(byte(addr>>24), byte(addr>>16), byte(addr>>8), byte(addr)).String()
}
