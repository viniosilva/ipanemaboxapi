package main

import (
	"database/sql"
	"flag"
	"fmt"
	"os"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/lib/pq"
)

var (
	host     = flag.String("host", "localhost", "db host to database")
	port     = flag.String("port", "5432", "db port to database")
	dbName   = flag.String("dbName", "public", "db name to database")
	ssl      = flag.Bool("ssl", false, "db ssl to database")
	username = flag.String("username", "admin", "db username to database")
	password = flag.String("password", "", "db password to database")
)

func main() {
	flag.Parse()

	connString := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s",
		*username, *password, *host, *port, *dbName, formatSslMode(*ssl))

	db, err := sql.Open("postgres", connString)
	handleError(err)
	defer db.Close()

	driver, err := postgres.WithInstance(db, &postgres.Config{})
	handleError(err)
	defer driver.Close()

	m, err := migrate.NewWithDatabaseInstance(
		"file://db/migrations",
		"postgres", driver)
	handleError(err)
	defer m.Close()

	err = m.Up()
	handleError(err)
}

func formatSslMode(sslMode bool) string {
	if sslMode {
		return "require"
	}

	return "disable"
}

func handleError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
