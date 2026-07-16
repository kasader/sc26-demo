package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
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
		listen    string
		blockTTL  time.Duration
	)
	flag.BoolVar(&debugMode, "debug", false, "Enable bpf_printk tracing (view via /sys/kernel/debug/tracing/trace_pipe).")
	flag.UintVar(&rate, "rate", 30, "Per-source packets/sec allowed before auto-block kicks in.")
	flag.StringVar(&listen, "listen", "0.0.0.0:5555", "HTTP control API address.")
	flag.DurationVar(&blockTTL, "block-ttl", 15*time.Second, "How long an auto-blocked source stays blocked.")
	flag.Parse()

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

	respondJSON := func(w http.ResponseWriter, status int, data any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(data)
	}

	var attachOnce sync.Once
	var attachErr error
	var xdpLink link.Link

	mux := http.NewServeMux()
	mux.HandleFunc("POST /setup", func(w http.ResponseWriter, r *http.Request) {
		reqData, err := io.ReadAll(r.Body)
		if err != nil {
			respondJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		var tmp struct {
			Address string `json:"address"`
			NicName string `json:"nic_name"`
		}
		if err := json.Unmarshal(reqData, &tmp); err != nil {
			respondJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		targetAddr, err := net.ResolveUDPAddr("udp", tmp.Address)
		if err != nil || targetAddr.IP.To4() == nil {
			respondJSON(w, http.StatusBadRequest, map[string]string{"error": "address must be an IPv4 host:port"})
			return
		}
		iface, err := net.InterfaceByName(tmp.NicName)
		if err != nil {
			respondJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		attachOnce.Do(func() {
			xdpLink, attachErr = link.AttachXDP(link.XDPOptions{
				Program:   objs.Guard,
				Interface: iface.Index,
				Flags:     link.XDPGenericMode, // required: XDP native mode isn't supported on veth
			})
		})
		if attachErr != nil {
			respondJSON(w, http.StatusInternalServerError, map[string]string{"error": attachErr.Error()})
			return
		}
		_ = xdpLink // kept alive for the process lifetime; closing it would detach the program

		key := guardAddressKey{
			Address: binary.BigEndian.Uint32(targetAddr.IP.To4()),
			Port:    uint16(targetAddr.Port),
		}
		if err := objs.Target.Update(uint32(0), key, ebpf.UpdateAny); err != nil {
			respondJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		dash.setTarget(tmp.Address, tmp.NicName)
		slog.Info("attached", "target", tmp.Address, "nic", tmp.NicName)
		respondJSON(w, http.StatusOK, map[string]string{"status": "attached"})
	})

	mux.HandleFunc("POST /block", func(w http.ResponseWriter, r *http.Request) {
		reqData, err := io.ReadAll(r.Body)
		if err != nil {
			respondJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		var items []struct {
			Address  string `json:"address"`
			Duration string `json:"duration"`
		}
		if err := json.Unmarshal(reqData, &items); err != nil {
			respondJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		var added []string
		for _, item := range items {
			addr, err := net.ResolveUDPAddr("udp", item.Address)
			if err != nil || addr.IP.To4() == nil {
				continue
			}
			d := blockTTL
			if item.Duration != "" {
				if parsed, err := time.ParseDuration(item.Duration); err == nil {
					d = parsed
				}
			}
			key := guardAddressKey{
				Address: binary.BigEndian.Uint32(addr.IP.To4()),
				Port:    uint16(addr.Port),
			}
			if err := objs.Blocklist.Put(key, uint8(1)); err != nil {
				continue
			}
			dash.block(item.Address, d, "manual")
			added = append(added, item.Address)
		}
		respondJSON(w, http.StatusOK, added)
	})

	mux.HandleFunc("POST /unblock-all", func(w http.ResponseWriter, r *http.Request) {
		var key guardAddressKey
		var toDelete []guardAddressKey
		iter := objs.Blocklist.Iterate()
		for iter.Next(&key, new(uint8)) {
			toDelete = append(toDelete, key)
		}
		for _, k := range toDelete {
			_ = objs.Blocklist.Delete(k)
		}
		dash.clear()
		respondJSON(w, http.StatusOK, map[string]string{"status": "cleared"})
	})

	go func() {
		if err := http.ListenAndServe(listen, mux); err != nil {
			log.Fatal("HTTP server:", err)
		}
	}()

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
