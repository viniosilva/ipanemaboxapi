package service

import (
	"context"

	"github.com/go-playground/validator/v10"
	"github.com/vinosilva/ipanemaboxapi/internal/dto"
	"github.com/vinosilva/ipanemaboxapi/internal/exception"
	"github.com/vinosilva/ipanemaboxapi/internal/model"
)

type CustomerService struct {
	customerRepository CustomerRepository
	logger             Logger
	validate           *validator.Validate
}

func NewCustomer(customerRepository CustomerRepository, logger Logger) *CustomerService {
	return &CustomerService{
		customerRepository: customerRepository,
		logger:             logger,
		validate:           validator.New(),
	}
}

func (impl *CustomerService) Create(ctx context.Context, data dto.CustomerCreateData) (*model.Customer, error) {
	if err := impl.validate.Struct(data); err != nil {
		return nil, exception.NewValidationException(err)
	}

	res, err := impl.customerRepository.Create(ctx, data)
	if err != nil {
		impl.logger.Error(err.Error())
	}

	return res, err
}

func (impl *CustomerService) FindAll(ctx context.Context, data dto.CustomerFindAllData) (*dto.CustomersResult, error) {
	if err := impl.validate.Struct(data); err != nil {
		return nil, exception.NewValidationException(err)
	}

	res, err := impl.customerRepository.FindAll(ctx, data)
	if err != nil {
		impl.logger.Error(err.Error())
	}

	return res, err
}

func (impl *CustomerService) FindByID(ctx context.Context, id int64) (*model.Customer, error) {
	res, err := impl.customerRepository.FindByID(ctx, id)
	if err != nil {
		if _, ok := err.(*exception.NotFoundException); !ok {
			impl.logger.Error(err.Error())
		}
	}

	return res, err
}

func (impl *CustomerService) Update(ctx context.Context, data dto.CustomerUpdateData) (*model.Customer, error) {
	if err := impl.validate.Struct(data); err != nil {
		return nil, exception.NewValidationException(err)
	}

	err := impl.customerRepository.Update(ctx, data)
	if err != nil {
		if _, ok := err.(*exception.NotFoundException); !ok {
			impl.logger.Error(err.Error())
		}
		return nil, err
	}

	res, err := impl.customerRepository.FindByID(ctx, data.ID)
	if err != nil {
		if _, ok := err.(*exception.NotFoundException); !ok {
			impl.logger.Error(err.Error())
		}
	}

	return res, err
}
