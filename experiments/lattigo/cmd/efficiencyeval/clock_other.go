//go:build !windows

package main

import (
	"fmt"
	"time"
)

// Outside Windows, ticks are nanoseconds from time.Now; run.json records this clock source.
const clockSource = "Go time.Now (monotonic)"

var clockStart = time.Now()

func clockFrequency() (int64, error) { return 1000000000, nil }

func qpcTicks() int64 { return int64(time.Since(clockStart)) }

func processMemory() (uint64, uint64, error) {
	return 0, 0, fmt.Errorf("process memory counters unavailable")
}
