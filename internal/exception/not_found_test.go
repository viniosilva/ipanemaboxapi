package exception

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNotFoundException(t *testing.T) {
	tests := map[string]struct {
		target  string
		wantErr string
	}{
		"should be an errors": {
			target:  "customer",
			wantErr: `customer not found`,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := NewNotFoundException(tt.target)

			assert.Equal(t, NotFoundExceptionName, got.Name)
			assert.Equal(t, tt.wantErr, got.Error())
		})
	}
}
