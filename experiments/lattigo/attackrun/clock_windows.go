package attackrun

import (
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var aCounter = syscall.NewLazyDLL("kernel32.dll").NewProc("QueryPerformanceCounter")
var aFrequency = syscall.NewLazyDLL("kernel32.dll").NewProc("QueryPerformanceFrequency")
var aOnce sync.Once
var aHz int64

func qpcEnabled() bool { return os.Getenv("DATASEAL_TIMING_CLOCK") == "qpc" }
func clockHz() int64 {
	aOnce.Do(func() {
		ok, _, err := aFrequency.Call(uintptr(unsafe.Pointer(&aHz)))
		if ok == 0 || aHz <= 0 || aHz > 1000000000 {
			panic(fmt.Sprintf("QPC frequency=%d error=%v", aHz, err))
		}
	})
	return aHz
}
func qpcTicks() int64 {
	var t int64
	ok, _, err := aCounter.Call(uintptr(unsafe.Pointer(&t)))
	if ok == 0 {
		panic(err)
	}
	return t
}
func ticksNS(d, hz int64) int64 {
	if d < 0 || hz <= 0 || hz > 1000000000 {
		panic("invalid counter delta/frequency")
	}
	return d/hz*1000000000 + (d%hz)*1000000000/hz
}
func attackNow() time.Time {
	if !qpcEnabled() {
		return time.Now()
	}
	hz := clockHz()
	t := qpcTicks()
	return time.Unix(t/hz, (t%hz)*1000000000/hz)
}
func attackClockInfo() Record {
	if !qpcEnabled() {
		return Record{"source": "Go time.Now", "unit": "ns"}
	}
	return Record{"source": "Windows QueryPerformanceCounter", "frequency_hz": clockHz(), "unit": "ns", "conversion": "quotient/remainder integer conversion", "version": "A-attack-QPC-v1", "legacy_diagnostic": "nested time.Now/Sub; diagnostic only; its clock reads add small overhead inside primary QPC interval", "timer_resolution_changed": false}
}
func measureQPCStage(r Record, name string, fn func()) {
	hz := clockHz()
	start := qpcTicks()
	legacyStart := time.Now()
	finished := false
	defer func() {
		legacyEnd := time.Now()
		end := qpcTicks()
		r[name+"_time_ns"] = ticksNS(end-start, hz)
		r["legacy_"+name+"_time_ns"] = legacyEnd.Sub(legacyStart).Nanoseconds()
		r["qpc_"+name+"_start_ticks"] = start
		r["qpc_"+name+"_end_ticks"] = end
		r["qpc_"+name+"_delta_ticks"] = end - start
		r["qpc_frequency_hz"] = hz
		if !finished {
			r["incomplete_timing_stage"] = name
		}
	}()
	fn()
	finished = true
}
