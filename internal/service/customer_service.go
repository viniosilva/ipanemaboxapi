package service

import (
	"context"

	"github.com/viniosilva/ipanemaboxapi/internal/dto"
	"github.com/viniosilva/ipanemaboxapi/internal/model"
)

type CustomerService struct {
	customerRepo CustomerRepository
}

type CustomerRepository interface {
	Create(ctx context.Context, customerDto dto.CreateCustomerDto) (*model.Customer, error)
}

func NewCustomerService(customerRepo CustomerRepository) *CustomerService {
	return &CustomerService{
		customerRepo: customerRepo,
	}
}

func (s *CustomerService) Create(ctx context.Context, customer dto.CreateCustomerDto) (*model.Customer, error) {
	res, err := s.customerRepo.Create(ctx, customer)
	return res, err
}
