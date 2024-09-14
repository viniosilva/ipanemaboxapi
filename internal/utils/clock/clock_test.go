package clock

import (
	"testing"
	"time"

	"github.com/go-playground/assert/v2"
)

func TestNow(t *testing.T) {
	fixedTime := time.Date(2024, time.May, 11, 18, 0, 0, 0, time.UTC)

	NowFunc = func() time.Time {
		return fixedTime
	}

	got := Now()

	assert.Equal(t, fixedTime, got)

	// Restore
	NowFunc = time.Now
}
