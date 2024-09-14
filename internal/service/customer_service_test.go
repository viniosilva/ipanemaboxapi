package service

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/viniosilva/ipanemaboxapi/internal/dto"
	"github.com/viniosilva/ipanemaboxapi/internal/exception"
	"github.com/viniosilva/ipanemaboxapi/internal/model"
	"github.com/viniosilva/ipanemaboxapi/mock"
	"go.uber.org/mock/gomock"
)

func TestCustomerService_Create(t *testing.T) {
	type args struct {
		ctx      context.Context
		customer dto.CustomerDataDto
	}
	tests := map[string]struct {
		mock    func(customerRepo *mock.MockCustomerRepository)
		args    args
		want    *model.Customer
		wantErr string
	}{
		"should be successful": {
			mock: func(customerRepo *mock.MockCustomerRepository) {
				customerRepo.EXPECT().
					Create(gomock.Any(), dto.CustomerDataDto{Name: "Testing"}).
					Return(&model.Customer{ID: 1, Name: "Testing"}, nil)
			},
			args: args{
				ctx:      context.TODO(),
				customer: dto.CustomerDataDto{Name: "Testing"},
			},
			want: &model.Customer{ID: 1, Name: "Testing"},
		},
		"should throw error": {
			mock: func(customerRepo *mock.MockCustomerRepository) {
				customerRepo.EXPECT().
					Create(gomock.Any(), dto.CustomerDataDto{Name: "Testing"}).
					Return(nil, fmt.Errorf("error"))
			},
			args: args{
				ctx:      context.TODO(),
				customer: dto.CustomerDataDto{Name: "Testing"},
			},
			wantErr: "error",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			customerRepoMock := mock.NewMockCustomerRepository(ctrl)
			tt.mock(customerRepoMock)

			svc := NewCustomerService(customerRepoMock)
			got, err := svc.Create(tt.args.ctx, tt.args.customer)

			assert.Equal(t, tt.want, got)
			if err != nil || tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
			}
		})
	}
}

func TestCustomerService_Find(t *testing.T) {
	type args struct {
		ctx context.Context
		id  int64
	}
	tests := map[string]struct {
		mock    func(customerRepo *mock.MockCustomerRepository)
		args    args
		want    *model.Customer
		wantErr string
	}{
		"should find customer successfully": {
			mock: func(customerRepo *mock.MockCustomerRepository) {
				customerRepo.EXPECT().
					Find(gomock.Any(), int64(1)).
					Return(&model.Customer{ID: 1, Name: "Testing"}, nil)
			},
			args: args{
				ctx: context.TODO(),
				id:  1,
			},
			want: &model.Customer{ID: 1, Name: "Testing"},
		},
		"should throw not found exception when customer not found": {
			mock: func(customerRepo *mock.MockCustomerRepository) {
				customerRepo.EXPECT().
					Find(gomock.Any(), int64(2)).
					Return(nil, exception.NewNotFoundException("customer not found by ID 2"))
			},
			args: args{
				ctx: context.TODO(),
				id:  2,
			},
			wantErr: "customer not found by ID 2",
		},
		"should throw error": {
			mock: func(customerRepo *mock.MockCustomerRepository) {
				customerRepo.EXPECT().
					Find(gomock.Any(), int64(2)).
					Return(nil, fmt.Errorf("error"))
			},
			args: args{
				ctx: context.TODO(),
				id:  2,
			},
			wantErr: "error",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			customerRepoMock := mock.NewMockCustomerRepository(ctrl)
			tt.mock(customerRepoMock)

			svc := NewCustomerService(customerRepoMock)
			got, err := svc.Find(tt.args.ctx, tt.args.id)

			assert.Equal(t, tt.want, got)
			if err != nil || tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
			}
		})
	}
}

func TestCustomerService_Update(t *testing.T) {
	type args struct {
		ctx      context.Context
		id       int64
		customer dto.CustomerDataDto
	}
	tests := map[string]struct {
		mock    func(customerRepo *mock.MockCustomerRepository)
		args    args
		want    *model.Customer
		wantErr string
	}{
		"should update customer successfully": {
			mock: func(customerRepo *mock.MockCustomerRepository) {
				customerRepo.EXPECT().
					Update(gomock.Any(), int64(1), dto.CustomerDataDto{Name: "Testing"}).
					Return(&model.Customer{ID: 1, Name: "Testing"}, nil)
			},
			args: args{
				ctx:      context.TODO(),
				id:       1,
				customer: dto.CustomerDataDto{Name: "Testing"},
			},
			want: &model.Customer{ID: 1, Name: "Testing"},
		},
		"should throw not found exception when customer not found": {
			mock: func(customerRepo *mock.MockCustomerRepository) {
				customerRepo.EXPECT().
					Update(gomock.Any(), int64(2), gomock.Any()).
					Return(nil, exception.NewNotFoundException("customer not found by ID 2"))
			},
			args: args{
				ctx:      context.TODO(),
				id:       2,
				customer: dto.CustomerDataDto{Name: "Testing"},
			},
			wantErr: "customer not found by ID 2",
		},
		"should throw error": {
			mock: func(customerRepo *mock.MockCustomerRepository) {
				customerRepo.EXPECT().
					Update(gomock.Any(), int64(2), gomock.Any()).
					Return(nil, fmt.Errorf("error"))
			},
			args: args{
				ctx:      context.TODO(),
				id:       2,
				customer: dto.CustomerDataDto{Name: "Testing"},
			},
			wantErr: "error",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			customerRepoMock := mock.NewMockCustomerRepository(ctrl)
			tt.mock(customerRepoMock)

			svc := NewCustomerService(customerRepoMock)
			got, err := svc.Update(tt.args.ctx, tt.args.id, tt.args.customer)

			assert.Equal(t, tt.want, got)
			if err != nil || tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
			}
		})
	}
}
