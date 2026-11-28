//go:build windows

package main

import (
	"fmt"
	"sync"
	"syscall"
	"unsafe"
)

const clockSource = "Windows QueryPerformanceCounter"

var (
	kernel32     = syscall.NewLazyDLL("kernel32.dll")
	qpcCounter   = kernel32.NewProc("QueryPerformanceCounter")
	qpcFrequency = kernel32.NewProc("QueryPerformanceFrequency")
	procMemInfo  = kernel32.NewProc("K32GetProcessMemoryInfo")
	procCurrent  = kernel32.NewProc("GetCurrentProcess")
	freqOnce     sync.Once
	freqHz       int64
	freqErr      error
)

// clockFrequency returns the QPC frequency; the collector refuses to run without it.
func clockFrequency() (int64, error) {
	freqOnce.Do(func() {
		ok, _, err := qpcFrequency.Call(uintptr(unsafe.Pointer(&freqHz)))
		if ok == 0 || freqHz <= 0 || freqHz > 1000000000 {
			freqErr = fmt.Errorf("QueryPerformanceFrequency unavailable: frequency=%d error=%v", freqHz, err)
		}
	})
	return freqHz, freqErr
}

// qpcTicks reads the raw counter. Used only for elapsed intervals.
func qpcTicks() int64 {
	var ticks int64
	ok, _, err := qpcCounter.Call(uintptr(unsafe.Pointer(&ticks)))
	if ok == 0 {
		panic(fmt.Sprintf("QueryPerformanceCounter: %v", err))
	}
	return ticks
}

type processMemoryCounters struct {
	cb                         uint32
	pageFaultCount             uint32
	peakWorkingSetSize         uintptr
	workingSetSize             uintptr
	quotaPeakPagedPoolUsage    uintptr
	quotaPagedPoolUsage        uintptr
	quotaPeakNonPagedPoolUsage uintptr
	quotaNonPagedPoolUsage     uintptr
	pagefileUsage              uintptr
	peakPagefileUsage          uintptr
}

// processMemory returns the peak and current working set in bytes; the peak
// covers the process lifetime.
func processMemory() (peak, current uint64, err error) {
	h, _, _ := procCurrent.Call()
	var c processMemoryCounters
	c.cb = uint32(unsafe.Sizeof(c))
	ok, _, e := procMemInfo.Call(h, uintptr(unsafe.Pointer(&c)), uintptr(c.cb))
	if ok == 0 {
		return 0, 0, fmt.Errorf("K32GetProcessMemoryInfo: %v", e)
	}
	return uint64(c.peakWorkingSetSize), uint64(c.workingSetSize), nil
}
