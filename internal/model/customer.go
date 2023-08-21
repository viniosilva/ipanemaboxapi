package model

import "time"

type Customer struct {
	ID        int64      `db:"id"`
	CreatedAt *time.Time `db:"created_at"`
	UpdatedAt *time.Time `db:"updated_at"`
	DeletedAt *time.Time `db:"deleted_at"`

	FullName string `db:"fullname"`
	Email    string `db:"email"`
}
