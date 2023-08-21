package repository

import (
	"context"
	"database/sql"
	"time"
)

//go:generate mockgen -source=./interface.go -destination=../../mock/repository_mocks.go -package=mock
type DB interface {
	PingContext(ctx context.Context) error
	NamedExecContext(ctx context.Context, query string, arg interface{}) (sql.Result, error)
	SelectContext(ctx context.Context, dest interface{}, query string, args ...interface{}) error
	GetContext(ctx context.Context, dest interface{}, query string, args ...interface{}) error
}

type ITime interface {
	Now() time.Time
}

type timeImpl struct{}

func (impl *timeImpl) Now() time.Time {
	return time.Now()
}
