package engine

import (
	"runtime"
	"sync"
)

// parallelThreshold is the smallest batch worth splitting across goroutines.
// Below it, dispatch/join overhead would outweigh whatever parallel crypto
// time it saves — which covers the common case of a single low-rate peer,
// the exact scenario this session spent most of its time debugging. That
// case should see zero behavioral change from this file existing.
const parallelThreshold = 16

// cryptoWorkers bounds how many goroutines a single batch's crypto work gets
// split across. One AEAD seal/open is independent of every other in the same
// batch (each has its own nonce derived from its own packet number), so
// unlike WireGuard's streaming design this needs no ordering machinery: every
// caller here already collects a whole batch before doing anything with it,
// so results just land at the same index job i was given, and get consumed
// in that order afterward regardless of which goroutine finished first or
// when.
var cryptoWorkers = runtime.NumCPU()

// parallelRange calls fn(i) for every i in [0, n), splitting the range into
// contiguous chunks run on separate goroutines when n meets parallelThreshold,
// and running it inline otherwise. fn(i) must only touch storage indexed by
// i — parallelRange guarantees disjoint index ranges per goroutine, nothing
// more.
func parallelRange(n int, fn func(i int)) {
	if n < parallelThreshold || cryptoWorkers <= 1 {
		for i := 0; i < n; i++ {
			fn(i)
		}
		return
	}

	workers := cryptoWorkers
	if workers > n {
		workers = n
	}
	chunk := (n + workers - 1) / workers

	var wg sync.WaitGroup
	for start := 0; start < n; start += chunk {
		end := start + chunk
		if end > n {
			end = n
		}
		wg.Add(1)
		go func(start, end int) {
			defer wg.Done()
			for i := start; i < end; i++ {
				fn(i)
			}
		}(start, end)
	}
	wg.Wait()
}
