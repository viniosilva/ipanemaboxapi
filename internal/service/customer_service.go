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
	Create(ctx context.Context, customerDto dto.CustomerDataDto) (*model.Customer, error)
	Find(ctx context.Context, id int64) (*model.Customer, error)
	List(ctx context.Context, page, limit int) (*dto.CustomersList, error)
	Update(ctx context.Context, id int64, customerDto dto.CustomerDataDto) (*model.Customer, error)
	Delete(ctx context.Context, id int64) error
}

func NewCustomerService(customerRepo CustomerRepository) *CustomerService {
	return &CustomerService{
		customerRepo: customerRepo,
	}
}

func (s *CustomerService) Create(ctx context.Context, customer dto.CustomerDataDto) (*model.Customer, error) {
	res, err := s.customerRepo.Create(ctx, customer)
	return res, err
}

func (s *CustomerService) Find(ctx context.Context, id int64) (*model.Customer, error) {
	res, err := s.customerRepo.Find(ctx, id)
	return res, err
}

func (s *CustomerService) List(ctx context.Context, page, limit int) (*dto.CustomersList, error) {
	return s.customerRepo.List(ctx, page, limit)
}

func (s *CustomerService) Update(ctx context.Context, id int64, customer dto.CustomerDataDto) (*model.Customer, error) {
	res, err := s.customerRepo.Update(ctx, id, customer)
	return res, err
}

func (s *CustomerService) Delete(ctx context.Context, id int64) error {
	err := s.customerRepo.Delete(ctx, id)
	return err
}
