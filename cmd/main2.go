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
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// m is created and cloned inside this helper function.
// When this function returns, m's stack frame is popped.
func createAndClone() map[string]X {
	m := map[string]X{}
	for i := range 1_000_000 {
		m[strconv.Itoa(i)] = X{}
	}

	for k := range m {
		delete(m, k)
	}

	// Clone m into m2 before returning
	return maps.Clone(m)
}

func main() {
	// m2 receives the clone; m is now completely out of scope
	m2 := createAndClone()

	// Measure heap memory with ONLY m2 alive in main
	heapAfterGC := getHeapAlloc()

	fmt.Printf("m2 len: %d\n", len(m2))
	fmt.Printf("Heap size with only m2 alive: ~%.2f MB\n", float64(heapAfterGC)/1024/1024)

	_ = m2
}
