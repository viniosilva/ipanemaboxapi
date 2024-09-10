package logger

import "log/slog"

func GetLogLevel(value string) slog.Level {
	res := map[string]slog.Level{
		"debug": slog.LevelDebug,
		"info":  slog.LevelInfo,
		"warn":  slog.LevelWarn,
		"error": slog.LevelError,
	}

	if _, ok := res[value]; !ok {
		return slog.LevelInfo
	}

	return res[value]
}
