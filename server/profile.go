package main

import (
	"os"
	"runtime"
	"runtime/pprof"
	"time"
)

// StartCPUProfile starts CPU profiling to the given file path.
// Returns a stop function that must be called to flush and close the profile.
func StartCPUProfile(path string) (stop func(), err error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	if err := pprof.StartCPUProfile(f); err != nil {
		f.Close()
		return nil, err
	}
	stop = func() {
		pprof.StopCPUProfile()
		f.Close()
	}
	return stop, nil
}

// WriteHeapProfile writes a heap profile to the given file path.
func WriteHeapProfile(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	runtime.GC()
	return pprof.WriteHeapProfile(f)
}

// WriteGoroutineProfile writes a goroutine profile to the given file path.
func WriteGoroutineProfile(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return pprof.Lookup("goroutine").WriteTo(f, 2)
}

// MemoryStats returns current memory allocation statistics.
func MemoryStats() map[string]interface{} {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return map[string]interface{}{
		"alloc_bytes":       m.Alloc,
		"total_alloc_bytes": m.TotalAlloc,
		"sys_bytes":         m.Sys,
		"heap_alloc_bytes":  m.HeapAlloc,
		"heap_sys_bytes":    m.HeapSys,
		"heap_objects":      m.HeapObjects,
		"stack_inuse_bytes": m.StackInuse,
		"num_gc":            m.NumGC,
		"goroutines":        runtime.NumGoroutine(),
		"next_gc_bytes":     m.NextGC,
		"gc_pause_total_ns": m.PauseTotalNs,
		"last_gc_ns":        m.LastGC,
	}
}

// ForceGC forces a garbage collection and returns the number of GC cycles.
func ForceGC() uint32 {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.NumGC
}

// ProfileSnapshot captures a point-in-time profile snapshot including
// memory stats, goroutine count, and optionally writes heap/goroutine profiles.
type ProfileSnapshot struct {
	Timestamp     time.Time
	Memory        map[string]interface{}
	Goroutines    int
	HeapFile      string // path to heap profile file (empty if not written)
	GoroutineFile string // path to goroutine profile file (empty if not written)
}

// CaptureProfile creates a profile snapshot, optionally writing heap and goroutine
// profiles to files under the given directory (if dir is non-empty).
func CaptureProfile(dir string) *ProfileSnapshot {
	snapshot := &ProfileSnapshot{
		Timestamp:  time.Now().UTC(),
		Memory:     MemoryStats(),
		Goroutines: runtime.NumGoroutine(),
	}

	if dir != "" {
		os.MkdirAll(dir, 0755)

		heapPath := dir + "/heap_" + snapshot.Timestamp.Format("20060102_150405") + ".prof"
		if err := WriteHeapProfile(heapPath); err == nil {
			snapshot.HeapFile = heapPath
		}

		goroutinePath := dir + "/goroutine_" + snapshot.Timestamp.Format("20060102_150405") + ".prof"
		if err := WriteGoroutineProfile(goroutinePath); err == nil {
			snapshot.GoroutineFile = goroutinePath
		}
	}

	return snapshot
}
