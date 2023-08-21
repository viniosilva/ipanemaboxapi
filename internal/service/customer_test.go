package service

import (
	"context"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/vinosilva/ipanemaboxapi/internal/dto"
	"github.com/vinosilva/ipanemaboxapi/internal/exception"
	"github.com/vinosilva/ipanemaboxapi/internal/model"
	"github.com/vinosilva/ipanemaboxapi/mock"
)

func TestCustomerService_NewCustomer(t *testing.T) {
	t.Run("should be success", func(t *testing.T) {
		//setup
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		customerRepositoryMock := mock.NewMockCustomerRepository(ctrl)
		loggerMock := mock.NewMockLogger(ctrl)

		// given
		got := NewCustomer(customerRepositoryMock, loggerMock)

		assert.NotNil(t, got)
	})
}

func TestCustomerService_Create(t *testing.T) {
	tm := time.Now()

	tests := map[string]struct {
		mock     func(customerRepository *mock.MockCustomerRepository, logger *mock.MockLogger)
		data     dto.CustomerCreateData
		want     *model.Customer
		wantErr  string
		wantErrs []string
	}{
		"should be success": {
			mock: func(customerRepository *mock.MockCustomerRepository, logger *mock.MockLogger) {
				customerRepository.EXPECT().Create(gomock.Any(), gomock.Any()).Return(&model.Customer{
					ID:        1,
					CreatedAt: &tm,
					UpdatedAt: &tm,
					FullName:  "full name",
					Email:     "email@email.com",
				}, nil)
			},
			data: dto.CustomerCreateData{
				FullName: "full name",
				Email:    "email@email.com",
			},
			want: &model.Customer{
				ID:        1,
				CreatedAt: &tm,
				UpdatedAt: &tm,
				FullName:  "full name",
				Email:     "email@email.com",
			},
		},
		"should throw error on validate": {
			mock: func(customerRepository *mock.MockCustomerRepository, logger *mock.MockLogger) {},
			data: dto.CustomerCreateData{
				Email: "invalid",
			},
			wantErrs: []string{
				"Key: 'CustomerCreateData.Email' Error:Field validation for 'Email' failed on the 'email' tag",
				"Key: 'CustomerCreateData.FullName' Error:Field validation for 'FullName' failed on the 'required' tag",
			},
		},
		"should throw error on customerRepository.Create": {
			mock: func(customerRepository *mock.MockCustomerRepository, logger *mock.MockLogger) {
				customerRepository.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil, fmt.Errorf("error"))
				logger.EXPECT().Error(gomock.Any())
			},
			data: dto.CustomerCreateData{
				FullName: "full name",
				Email:    "email@email.com",
			},
			wantErr: "error",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			//setup
			ctx := context.Background()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			customerRepositoryMock := mock.NewMockCustomerRepository(ctrl)
			loggerMock := mock.NewMockLogger(ctrl)
			tt.mock(customerRepositoryMock, loggerMock)

			// given
			customerService := NewCustomer(customerRepositoryMock, loggerMock)

			// when
			got, err := customerService.Create(ctx, tt.data)

			assert.Equal(t, tt.want, got)

			// then
			if err != nil || tt.wantErr != "" || len(tt.wantErrs) > 0 {
				if e, ok := err.(*exception.ValidationException); ok {
					sort.Strings(e.Errors)
					assert.Equal(t, e.Errors, tt.wantErrs)
				} else {
					assert.EqualError(t, err, tt.wantErr)
				}
			}
		})
	}
}

func TestCustomerService_FindAll(t *testing.T) {
	tm := time.Now()

	tests := map[string]struct {
		mock     func(customerRepository *mock.MockCustomerRepository, logger *mock.MockLogger)
		data     dto.CustomerFindAllData
		want     *dto.CustomersResult
		wantErr  string
		wantErrs []string
	}{
		"should return customers": {
			mock: func(customerRepository *mock.MockCustomerRepository, logger *mock.MockLogger) {
				customerRepository.EXPECT().FindAll(gomock.Any(), dto.CustomerFindAllData{Page: 1, Size: 10}).Return(&dto.CustomersResult{
					Data: []model.Customer{
						{
							ID:        1,
							CreatedAt: &tm,
							UpdatedAt: &tm,
							FullName:  "full name",
							Email:     "email@email.com",
						},
					}}, nil)
			},
			data: dto.CustomerFindAllData{Page: 1, Size: 10},
			want: &dto.CustomersResult{
				Data: []model.Customer{
					{
						ID:        1,
						CreatedAt: &tm,
						UpdatedAt: &tm,
						FullName:  "full name",
						Email:     "email@email.com",
					},
				},
			},
		},
		"should throw error on validate data": {
			mock: func(customerRepository *mock.MockCustomerRepository, logger *mock.MockLogger) {},
			data: dto.CustomerFindAllData{Page: 0, Size: -1},
			wantErrs: []string{
				"Key: 'CustomerFindAllData.Page' Error:Field validation for 'Page' failed on the 'gt' tag",
				"Key: 'CustomerFindAllData.Size' Error:Field validation for 'Size' failed on the 'gt' tag",
			},
		},
		"should throw error on customerRepository.FindAll": {
			mock: func(customerRepository *mock.MockCustomerRepository, logger *mock.MockLogger) {
				customerRepository.EXPECT().FindAll(gomock.Any(), dto.CustomerFindAllData{Page: 1, Size: 10}).Return(nil, fmt.Errorf("error"))
				logger.EXPECT().Error(gomock.Any())
			},
			data:    dto.CustomerFindAllData{Page: 1, Size: 10},
			wantErr: "error",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			//setup
			ctx := context.Background()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			customerRepositoryMock := mock.NewMockCustomerRepository(ctrl)
			loggerMock := mock.NewMockLogger(ctrl)
			tt.mock(customerRepositoryMock, loggerMock)

			// given
			customerService := NewCustomer(customerRepositoryMock, loggerMock)

			// when
			got, err := customerService.FindAll(ctx, tt.data)

			assert.Equal(t, tt.want, got)

			// then
			if err != nil || tt.wantErr != "" || len(tt.wantErrs) > 0 {
				if e, ok := err.(*exception.ValidationException); ok {
					sort.Strings(e.Errors)
					assert.Equal(t, e.Errors, tt.wantErrs)
				} else {
					assert.EqualError(t, err, tt.wantErr)
				}
			}
		})
	}
}

func TestCustomerService_FindByID(t *testing.T) {
	tm := time.Now()

	tests := map[string]struct {
		mock    func(customerRepository *mock.MockCustomerRepository, logger *mock.MockLogger)
		id      int64
		want    *model.Customer
		wantErr string
	}{
		"should return customer": {
			mock: func(customerRepository *mock.MockCustomerRepository, logger *mock.MockLogger) {
				customerRepository.EXPECT().FindByID(gomock.Any(), int64(1)).Return(&model.Customer{
					ID:        1,
					CreatedAt: &tm,
					UpdatedAt: &tm,
					FullName:  "full name",
					Email:     "email@email.com",
				}, nil)
			},
			id: 1,
			want: &model.Customer{
				ID:        1,
				CreatedAt: &tm,
				UpdatedAt: &tm,
				FullName:  "full name",
				Email:     "email@email.com",
			},
		},
		"should throw not found exception on customerRepository.FindByID": {
			mock: func(customerRepository *mock.MockCustomerRepository, logger *mock.MockLogger) {
				customerRepository.EXPECT().FindByID(gomock.Any(), int64(1)).Return(nil, exception.NewNotFoundException("customer"))
			},
			id:      1,
			wantErr: "customer not found",
		},
		"should throw error on customerRepository.FindByID": {
			mock: func(customerRepository *mock.MockCustomerRepository, logger *mock.MockLogger) {
				customerRepository.EXPECT().FindByID(gomock.Any(), int64(1)).Return(nil, fmt.Errorf("error"))
				logger.EXPECT().Error(gomock.Any())
			},
			id:      1,
			wantErr: "error",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			//setup
			ctx := context.Background()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			customerRepositoryMock := mock.NewMockCustomerRepository(ctrl)
			loggerMock := mock.NewMockLogger(ctrl)
			tt.mock(customerRepositoryMock, loggerMock)

			// given
			customerService := NewCustomer(customerRepositoryMock, loggerMock)

			// when
			got, err := customerService.FindByID(ctx, tt.id)

			assert.Equal(t, tt.want, got)

			// then
			if err != nil || tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
			}
		})
	}
}

func TestCustomerService_Update(t *testing.T) {
	tm := time.Now()

	tests := map[string]struct {
		mock     func(customerRepository *mock.MockCustomerRepository, logger *mock.MockLogger)
		data     dto.CustomerUpdateData
		want     *model.Customer
		wantErr  string
		wantErrs []string
	}{
		"should be success": {
			mock: func(customerRepository *mock.MockCustomerRepository, logger *mock.MockLogger) {
				customerRepository.EXPECT().Update(gomock.Any(), gomock.Any()).Return(nil)
				customerRepository.EXPECT().FindByID(gomock.Any(), int64(1)).Return(&model.Customer{
					ID:        1,
					CreatedAt: &tm,
					UpdatedAt: &tm,
					FullName:  "full name",
					Email:     "email@email.com",
				}, nil)
			},
			data: dto.CustomerUpdateData{
				ID:        1,
				FullName:  "full name",
				Email:     "email@email.com",
				UpdatedAt: tm,
			},
			want: &model.Customer{
				ID:        1,
				CreatedAt: &tm,
				UpdatedAt: &tm,
				FullName:  "full name",
				Email:     "email@email.com",
			},
		},
		"should throw error on validate data": {
			mock: func(customerRepository *mock.MockCustomerRepository, logger *mock.MockLogger) {},
			data: dto.CustomerUpdateData{
				ID:        1,
				Email:     "invalid",
				UpdatedAt: tm,
			},
			wantErrs: []string{
				"Key: 'CustomerUpdateData.Email' Error:Field validation for 'Email' failed on the 'email' tag",
			},
		},
		"should throw not found exception on customerRepository.Update": {
			mock: func(customerRepository *mock.MockCustomerRepository, logger *mock.MockLogger) {
				customerRepository.EXPECT().Update(gomock.Any(), gomock.Any()).Return(exception.NewNotFoundException("customer"))
			},
			data: dto.CustomerUpdateData{
				ID:        1,
				FullName:  "full name",
				Email:     "email@email.com",
				UpdatedAt: tm,
			},
			wantErr: "customer not found",
		},
		"should throw not found exception on customerRepository.FindByID": {
			mock: func(customerRepository *mock.MockCustomerRepository, logger *mock.MockLogger) {
				customerRepository.EXPECT().Update(gomock.Any(), gomock.Any()).Return(nil)
				customerRepository.EXPECT().FindByID(gomock.Any(), int64(1)).Return(nil, exception.NewNotFoundException("customer"))
			},
			data: dto.CustomerUpdateData{
				ID:        1,
				FullName:  "full name",
				Email:     "email@email.com",
				UpdatedAt: tm,
			},
			wantErr: "customer not found",
		},
		"should throw error on customerRepository.Update": {
			mock: func(customerRepository *mock.MockCustomerRepository, logger *mock.MockLogger) {
				customerRepository.EXPECT().Update(gomock.Any(), gomock.Any()).Return(fmt.Errorf("error"))
				logger.EXPECT().Error(gomock.Any())
			},
			data: dto.CustomerUpdateData{
				ID:        1,
				FullName:  "full name",
				Email:     "email@email.com",
				UpdatedAt: tm,
			},
			wantErr: "error",
		},
		"should throw error on customerRepository.FindByID": {
			mock: func(customerRepository *mock.MockCustomerRepository, logger *mock.MockLogger) {
				customerRepository.EXPECT().Update(gomock.Any(), gomock.Any()).Return(nil)
				customerRepository.EXPECT().FindByID(gomock.Any(), int64(1)).Return(nil, fmt.Errorf("error"))
				logger.EXPECT().Error(gomock.Any())
			},

			data: dto.CustomerUpdateData{
				ID:        1,
				FullName:  "full name",
				Email:     "email@email.com",
				UpdatedAt: tm,
			},
			wantErr: "error",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			//setup
			ctx := context.Background()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			customerRepositoryMock := mock.NewMockCustomerRepository(ctrl)
			loggerMock := mock.NewMockLogger(ctrl)
			tt.mock(customerRepositoryMock, loggerMock)

			// given
			customerService := NewCustomer(customerRepositoryMock, loggerMock)

			// when
			got, err := customerService.Update(ctx, tt.data)

			// then
			if err != nil || tt.wantErr != "" || len(tt.wantErrs) > 0 {
				if e, ok := err.(*exception.ValidationException); ok {
					sort.Strings(e.Errors)
					assert.Equal(t, e.Errors, tt.wantErrs)
				} else {
					assert.EqualError(t, err, tt.wantErr)
				}

				return
			}

			assert.Equal(t, tt.want, got)
		})
	}
}
