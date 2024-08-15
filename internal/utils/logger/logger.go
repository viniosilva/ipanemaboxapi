package logger

import "log/slog"

func GetLogLevel(value uint) slog.Level {
	res := map[uint]slog.Level{
		5: slog.LevelDebug,
		4: slog.LevelInfo,
		3: slog.LevelWarn,
		2: slog.LevelError,
	}

	if _, ok := res[value]; !ok {
		return slog.LevelInfo
	}

	return res[value]
}
