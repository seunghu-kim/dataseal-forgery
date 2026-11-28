//go:build !windows

package attackrun

import (
	"fmt"
	"os"
	"time"
)

// Outside Windows a request for the QPC clock is refused, not silently replaced by time.Now.
func qpcEnabled() bool {
	if os.Getenv("DATASEAL_TIMING_CLOCK") == "qpc" {
		fmt.Fprintln(os.Stderr, "DATASEAL_TIMING_CLOCK=qpc requires Windows QueryPerformanceCounter")
		os.Exit(1)
	}
	return false
}

func attackNow() time.Time { return time.Now() }

func attackClockInfo() Record {
	qpcEnabled()
	return Record{"source": "Go time.Now", "unit": "ns"}
}

func measureQPCStage(r Record, name string, fn func()) { panic("QPC unavailable") }
