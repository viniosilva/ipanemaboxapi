package logger

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetLogLevel(t *testing.T) {
	type args struct {
		value uint
	}
	tests := map[string]struct {
		args args
		want slog.Level
	}{
		"should return error level when value is 2": {
			args: args{value: 2},
			want: slog.LevelError,
		},
		"should return warn level when value is 3": {
			args: args{value: 3},
			want: slog.LevelWarn,
		},
		"should return info level when value is 4": {
			args: args{value: 4},
			want: slog.LevelInfo,
		},
		"should return debug level when value is 5": {
			args: args{value: 5},
			want: slog.LevelDebug,
		},
		"should return default info level when value is invalid": {
			args: args{value: 6},
			want: slog.LevelInfo,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := GetLogLevel(tt.args.value)
			assert.Equal(t, tt.want, got)
		})
	}
}
