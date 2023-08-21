package repository

import (
	"context"
)

type HealthRepository struct {
	db DB
}

func NewHealth(db DB) *HealthRepository {
	return &HealthRepository{
		db: db,
	}
}

func (impl *HealthRepository) Ping(ctx context.Context) error {
	return impl.db.PingContext(ctx)
}
