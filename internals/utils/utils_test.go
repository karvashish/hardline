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
	sleepFn = func(time.Duration) {}
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
	if after-before > 1 {
		t.Fatalf("expected throbber to stop, before=%d after=%d", before, after)
	}
}
