package main

import (
	"fmt"
	"maps"
	"runtime"
	"strconv"
)

type X struct {
	a, b, c, d, e, f, g, h uint64
}

func getHeapAlloc() uint64 {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

func main() {
	m := map[string]X{}
	for i := range 1_000_000 {
		m[strconv.Itoa(i)] = X{}
	}

	for k := range m {
		delete(m, k)
	}

	allocBefore := getHeapAlloc()

	// Clone the empty map
	m2 := maps.Clone(m)

	// Drop reference to original map and run GC
	m = nil
	allocAfter := getHeapAlloc()

	fmt.Printf("m2 len: %d\n", len(m2))
	fmt.Printf("Heap size before m GC: ~%.2f MB\n", float64(allocBefore)/1024/1024)
	fmt.Printf("Heap size after m GC:  ~%.2f MB\n", float64(allocAfter)/1024/1024)
}
