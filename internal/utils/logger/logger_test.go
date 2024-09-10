package logger

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetLogLevel(t *testing.T) {
	type args struct {
		value string
	}
	tests := map[string]struct {
		args args
		want slog.Level
	}{
		"should return error level": {
			args: args{value: "error"},
			want: slog.LevelError,
		},
		"should return warn level": {
			args: args{value: "warn"},
			want: slog.LevelWarn,
		},
		"should return info level": {
			args: args{value: "info"},
			want: slog.LevelInfo,
		},
		"should return debug level": {
			args: args{value: "debug"},
			want: slog.LevelDebug,
		},
		"should return default info level when value is invalid": {
			args: args{value: "invalid"},
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
