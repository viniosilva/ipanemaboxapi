package exception

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewNotFoundException(t *testing.T) {
	tests := map[string]struct {
		msg  string
		args []any
		want string
	}{
		"should return error when there are not args": {
			msg:  "resource not found",
			want: "resource not found",
		},
		"should return error when there are args": {
			msg:  "resource with ID %d not found",
			args: []any{123},
			want: "resource with ID 123 not found",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := NewNotFoundException(tt.msg, tt.args...)

			assert.IsType(t, &NotFoundException{}, err)
			assert.Equal(t, tt.want, err.Error())
		})
	}
}
