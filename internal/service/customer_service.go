package service

import (
	"context"

	"github.com/viniosilva/ipanemaboxapi/internal/dto"
	"github.com/viniosilva/ipanemaboxapi/internal/model"
)

type CustomerService struct{}

func NewCustomerService() *CustomerService {
	return &CustomerService{}
}

func (impl *CustomerService) Create(ctx context.Context, customer dto.CreateCustomerDto) (*model.Customer, error) {
	return &model.Customer{
		ID:   1,
		Name: customer.Name,
	}, nil
}
