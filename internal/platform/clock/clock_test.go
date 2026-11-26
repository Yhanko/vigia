package clock

import (
	"testing"
	"time"
)

func TestSystemIsUTC(t *testing.T) {
	if loc := (System{}).Now().Location(); loc != time.UTC {
		t.Fatalf("System.Now() location = %v, want UTC", loc)
	}
}

func TestFake(t *testing.T) {
	start := time.Date(2026, 11, 26, 12, 0, 0, 0, time.FixedZone("WAT", 3600))
	c := NewFake(start)

	if !c.Now().Equal(start) || c.Now().Location() != time.UTC {
		t.Fatalf("NewFake: got %v", c.Now())
	}
	c.Advance(5 * time.Minute)
	if got := c.Now().Sub(start); got != 5*time.Minute {
		t.Fatalf("Advance: elapsed %v, want 5m", got)
	}

	var _ Clock = c
	var _ Clock = System{}
}
