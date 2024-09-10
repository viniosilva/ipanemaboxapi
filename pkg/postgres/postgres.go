package postgres

import (
	"fmt"
	"log/slog"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

func Connect(host, port, dbName, username, password string, sslMode bool) (*sqlx.DB, error) {
	connString := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s",
		username, password, host, port, dbName, formatSslMode(sslMode))

	db, err := sqlx.Open("postgres", connString)
	if err != nil {
		return nil, err
	}

	if err = db.Ping(); err != nil {
		return nil, err
	}

	slog.Info(fmt.Sprintf("postgres connected (%s:%s)", host, port))
	return db, nil
}

func formatSslMode(sslMode bool) string {
	if sslMode {
		return "require"
	}

	return "disable"
}
