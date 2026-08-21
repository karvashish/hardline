package utils

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestThrobberStops(t *testing.T) {
	prevSleep := sleepFn
	prevTickf := tickf
	defer func() {
		sleepFn = prevSleep
		tickf = prevTickf
	}()

	var count atomic.Int32
	sleepFn = func(time.Duration, <-chan struct{}) {}
	tickf = func(string, ...any) {
		count.Add(1)
	}

	stop := Throbber()
	time.Sleep(10 * time.Millisecond)
	stop()
	before := count.Load()
	time.Sleep(10 * time.Millisecond)
	after := count.Load()

	if before == 0 {
		t.Fatal("expected throbber to emit progress")
	}
	if after != before {
		t.Fatalf("stop must return only once the worker is done, before=%d after=%d", before, after)
	}
}

func TestThrobberStopInterruptsTheSleep(t *testing.T) {
	prevTickf := tickf
	defer func() { tickf = prevTickf }()
	tickf = func(string, ...any) {}

	// The real sleepFn is in play here: the first delay is ~150ms, so a stop that waited it out
	// would not return inside this budget.
	stop := Throbber()
	time.Sleep(200 * time.Millisecond)
	returned := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		stop()
		returned <- time.Since(start)
	}()

	select {
	case took := <-returned:
		if took > 50*time.Millisecond {
			t.Fatalf("stop waited out the current sleep interval: %v", took)
		}
	case <-time.After(time.Second):
		t.Fatal("stop did not return")
	}
}
