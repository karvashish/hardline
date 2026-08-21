package utils

import (
	"math"
	"time"

	"github.com/karvashish/hardline/pkg/logger"
)

var sleepFn = func(d time.Duration, cancel <-chan struct{}) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-cancel:
	case <-timer.C:
	}
}
var tickf = logger.Tickf

func Throbber() func() {
	const total = 100
	progress := 0
	stop := make(chan struct{})
	done := make(chan struct{})

	expDelay := func(p int) time.Duration {
		delay := math.Exp((float64(p)/float64(total))*3.0) * 150.0
		return time.Duration(delay) * time.Millisecond
	}

	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if progress >= total {
				progress = 0
			}
			tickf(".")
			progress++
			sleepFn(expDelay(progress), stop)
		}
	}()

	// The sleep waits on stop as well as the clock, so joining the worker here costs nothing and
	// is what makes stop() mean the last dot has been printed.
	return func() {
		close(stop)
		<-done
	}
}
