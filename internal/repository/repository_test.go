package repository

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRepository_getLimitAndOffset(t *testing.T) {
	tests := map[string]struct {
		page       int
		size       int
		wantLimit  int
		wantOffset int
	}{
		"should return limit 10 and offset 0 when page is 1 and size is 1": {
			page:       1,
			size:       1,
			wantLimit:  1,
			wantOffset: 0,
		},
		"should return limit 10 and offset 10 when page is 2 and size is 10": {
			page:       2,
			size:       10,
			wantLimit:  10,
			wantOffset: 10,
		},
		"should return limit 100 and offset 220 when page is 22 and size is 100": {
			page:       22,
			size:       100,
			wantLimit:  100,
			wantOffset: 2100,
		},
		"should return limit 20 and offset 0 when page is 0 and size is 20": {
			page:       0,
			size:       20,
			wantLimit:  20,
			wantOffset: 0,
		},
		"should return limit 10 and offset 10 when page is 2 and size is -1": {
			page:       2,
			size:       -1,
			wantLimit:  10,
			wantOffset: 10,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			// given
			repository := &Repository{}

			// when
			limit, offset := repository.getLimitAndOffset(tt.page, tt.size)

			// then
			assert.Equal(t, tt.wantLimit, limit)
			assert.Equal(t, tt.wantOffset, offset)
		})
	}
}
