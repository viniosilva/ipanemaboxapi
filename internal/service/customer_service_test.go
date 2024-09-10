package service

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/viniosilva/ipanemaboxapi/internal/dto"
	"github.com/viniosilva/ipanemaboxapi/internal/model"
	"github.com/viniosilva/ipanemaboxapi/mock"
	"go.uber.org/mock/gomock"
)

func TestCustomerService_Create(t *testing.T) {
	type args struct {
		customer dto.CreateCustomerDto
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
					Create(gomock.Any(), dto.CreateCustomerDto{Name: "Testing"}).
					Return(&model.Customer{ID: 1, Name: "Testing"}, nil)
			},
			args: args{
				customer: dto.CreateCustomerDto{Name: "Testing"},
			},
			want: &model.Customer{ID: 1, Name: "Testing"},
		},
		"should throw error": {
			mock: func(customerRepo *mock.MockCustomerRepository) {
				customerRepo.EXPECT().
					Create(gomock.Any(), dto.CreateCustomerDto{Name: "Testing"}).
					Return(nil, fmt.Errorf("error"))
			},
			args: args{
				customer: dto.CreateCustomerDto{Name: "Testing"},
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

			got, err := svc.Create(context.Background(), tt.args.customer)

			assert.Equal(t, tt.want, got)
			if err != nil || tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
			}
		})
	}
}
