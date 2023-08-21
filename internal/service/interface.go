package service

import (
	"context"

	"github.com/vinosilva/ipanemaboxapi/internal/dto"
	"github.com/vinosilva/ipanemaboxapi/internal/model"
)

//go:generate mockgen -source=./interface.go -destination=../../mock/service_mocks.go -package=mock
type Logger interface {
	Error(args ...interface{})
}

type HealthRepository interface {
	Ping(ctx context.Context) error
}

type CustomerRepository interface {
	Create(ctx context.Context, data dto.CustomerCreateData) (*model.Customer, error)
	FindAll(ctx context.Context, data dto.CustomerFindAllData) (*dto.CustomersResult, error)
	FindByID(ctx context.Context, id int64) (*model.Customer, error)
	Update(ctx context.Context, data dto.CustomerUpdateData) error
}
