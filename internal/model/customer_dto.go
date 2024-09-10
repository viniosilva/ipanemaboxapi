package model

type Customer struct {
	ID   int64  `db:"id"`
	Name string `db:"name"`
}
