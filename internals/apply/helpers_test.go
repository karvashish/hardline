package apply

import (
	"testing"
	"time"

	"github.com/karvashish/hardline/pkg/profile"
)

func TestFormatShortDuration(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want string
	}{
		{-time.Second, "0ms"},
		{0, "0ms"},
		{423 * time.Millisecond, "423ms"},
		{4700 * time.Millisecond, "4.7s"},
		{59 * time.Second, "59.0s"},
		{5*time.Minute + 18*time.Second, "5m18s"},
		{time.Minute, "1m0s"},
	}
	for _, c := range cases {
		if got := formatShortDuration(c.in); got != c.want {
			t.Errorf("formatShortDuration(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCountApplySteps(t *testing.T) {
	if got := countApplySteps(nil); got != 0 {
		t.Errorf("nil profile: got %d, want 0", got)
	}
	if got := countApplySteps(&profile.Profile{}); got != 0 {
		t.Errorf("empty profile: got %d, want 0", got)
	}
	p := &profile.Profile{ActionFiles: []profile.ActionFile{
		{Steps: []profile.Step{{}, {}, {}}},
		{Steps: []profile.Step{{}}},
	}}
	if got := countApplySteps(p); got != 4 {
		t.Errorf("two action files: got %d, want 4", got)
	}
}
