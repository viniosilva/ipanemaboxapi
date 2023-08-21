package infra

import (
	"fmt"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
)

func MySQLConnect(username, password, host, port, database string,
	connMaxLifetime time.Duration, maxOpenConns, maxIdleConns int) (*sqlx.DB, error) {
	stringConn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true",
		username, password, host, port, database)

	db, err := sqlx.Open("mysql", stringConn)
	if err != nil {
		return nil, err
	}

	db.SetConnMaxLifetime(connMaxLifetime)
	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)

	if err := db.Ping(); err != nil {
		return nil, err
	}

	return db, nil
}
