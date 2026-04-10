package utils

import (
	"math"
	"time"

	"github.com/karvashish/hardline/pkg/logger"
)

var sleepFn = time.Sleep
var tickf = logger.Tickf

func Throbber() func() {
	const total = 100
	progress := 0
	stop := make(chan struct{})

	expDelay := func(p int) time.Duration {
		delay := math.Exp((float64(p)/float64(total))*3.0) * 150.0
		return time.Duration(delay) * time.Millisecond
	}

	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				if progress >= total {
					progress = 0
				}
				tickf(".")
				progress++
				sleepFn(expDelay(progress))
			}
		}
	}()

	return func() {
		close(stop)
	}
}
