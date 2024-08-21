package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/viniosilva/ipanemaboxapi/internal/dto"
	"github.com/viniosilva/ipanemaboxapi/internal/model"
)

func TestCustomerService_Create(t *testing.T) {
	type args struct {
		customer dto.CreateCustomerDto
	}
	tests := map[string]struct {
		args    args
		want    *model.Customer
		wantErr string
	}{
		"should be successful": {
			args: args{
				customer: dto.CreateCustomerDto{Name: "Testing"},
			},
			want: &model.Customer{ID: 1, Name: "Testing"},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			svc := NewCustomerService()

			got, err := svc.Create(context.Background(), tt.args.customer)

			assert.Equal(t, tt.want, got)
			if err != nil || tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
			}
		})
	}
}
