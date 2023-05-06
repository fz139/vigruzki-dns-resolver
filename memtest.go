package main

import (
	"runtime"
	"runtime/debug"
)

func memTest() uint64 {
	var m runtime.MemStats
	debug.FreeOSMemory()
	runtime.ReadMemStats(&m)
	return m.StackInuse + m.HeapInuse
}
