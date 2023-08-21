package controller

import (
	"context"

	"github.com/vinosilva/ipanemaboxapi/internal/dto"
	"github.com/vinosilva/ipanemaboxapi/internal/model"
)

//go:generate mockgen -source=./interface.go -destination=../../mock/controlller_mocks.go -package=mock
type HealthService interface {
	Check(ctx context.Context) error
}

type CustomerService interface {
	Create(ctx context.Context, data dto.CustomerCreateData) (*model.Customer, error)
	FindAll(ctx context.Context, data dto.CustomerFindAllData) (*dto.CustomersResult, error)
	FindByID(ctx context.Context, id int64) (*model.Customer, error)
	Update(ctx context.Context, data dto.CustomerUpdateData) (*model.Customer, error)
}
