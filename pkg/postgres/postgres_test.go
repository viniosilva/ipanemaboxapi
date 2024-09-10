package postgres

import (
	"testing"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
)

func Test_formatSslMode(t *testing.T) {
	type args struct {
		sslMode bool
	}
	tests := map[string]struct {
		args args
		want string
	}{
		"should returns require": {
			args: args{sslMode: true},
			want: "require",
		},
		"should returns disable": {
			args: args{sslMode: false},
			want: "disable",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := formatSslMode(tt.args.sslMode)

			assert.Equal(t, tt.want, got)
		})
	}
}
