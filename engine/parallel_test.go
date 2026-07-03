package engine

import "testing"

func TestParallelRangeVisitsEveryIndexOnce(t *testing.T) {
	sizes := []int{0, 1, parallelThreshold - 1, parallelThreshold, parallelThreshold + 1, 128, 1000}
	for _, n := range sizes {
		seen := make([]int, n)
		parallelRange(n, func(i int) {
			seen[i]++ // disjoint index per call; a race here would mean parallelRange is broken
		})
		for i, count := range seen {
			if count != 1 {
				t.Fatalf("n=%d: index %d visited %d times, want 1", n, i, count)
			}
		}
	}
}

func TestParallelRangeForcedParallelPath(t *testing.T) {
	// Exercise the goroutine-splitting branch specifically, independent of
	// however many cores this machine happens to have.
	orig := cryptoWorkers
	cryptoWorkers = 8
	defer func() { cryptoWorkers = orig }()

	n := 500
	seen := make([]int32, n)
	parallelRange(n, func(i int) {
		seen[i] = 1
	})
	for i, v := range seen {
		if v != 1 {
			t.Fatalf("index %d not visited exactly once (got %d)", i, v)
		}
	}
}
