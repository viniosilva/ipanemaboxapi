package controller

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/viniosilva/ipanemaboxapi/internal/controller/presenter"
	"github.com/viniosilva/ipanemaboxapi/internal/dto"
	"github.com/viniosilva/ipanemaboxapi/internal/model"
	"github.com/viniosilva/ipanemaboxapi/mock"
	"go.uber.org/mock/gomock"
)

func TestNewCustomerController(t *testing.T) {
	got := NewCustomerController(nil)

	assert.NotNil(t, got)
}

func TestCustomerController_Create(t *testing.T) {
	type args struct {
		payload string
	}
	tests := map[string]struct {
		mock       func(customerSvc *mock.MockCustomerService)
		args       args
		wantStatus int
		want       presenter.CustomerRes
		wantErr    presenter.ErrorRes
	}{
		"should be successful": {
			mock: func(customerSvc *mock.MockCustomerService) {
				customerSvc.EXPECT().
					Create(gomock.Any(), dto.CreateCustomerDto{Name: "Testing"}).
					Return(&model.Customer{ID: 1, Name: "Testing"}, nil)
			},
			args: args{
				payload: `{"name":"Testing"}`,
			},
			wantStatus: http.StatusCreated,
			want:       presenter.CustomerRes{ID: 1, Name: "Testing"},
		},
		"should throw error when payload is empty": {
			mock:       func(customerSvc *mock.MockCustomerService) {},
			args:       args{payload: "{}"},
			wantStatus: http.StatusBadRequest,
			wantErr:    presenter.ErrorRes{Message: "Key: 'CustomerReq.Name' Error:Field validation for 'Name' failed on the 'required' tag"},
		},
		"should throw internal server error": {
			mock: func(customerSvc *mock.MockCustomerService) {
				customerSvc.EXPECT().
					Create(gomock.Any(), dto.CreateCustomerDto{Name: "Testing"}).
					Return(nil, fmt.Errorf("error"))
			},
			args: args{
				payload: `{"name":"Testing"}`,
			},
			wantStatus: http.StatusInternalServerError,
			wantErr:    presenter.ErrorRes{Message: presenter.INTERNAL_SERVER_ERROR_MSG},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			customerSvcMock := mock.NewMockCustomerService(ctrl)
			tt.mock(customerSvcMock)

			controller := NewCustomerController(customerSvcMock)
			r := gin.Default()
			r.POST("/api/v1/customers", controller.Create)

			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodPost, "/api/v1/customers", strings.NewReader(tt.args.payload))
			r.ServeHTTP(w, req)

			var body presenter.CustomerRes
			json.Unmarshal(w.Body.Bytes(), &body)
			var bodyErr presenter.ErrorRes
			json.Unmarshal(w.Body.Bytes(), &bodyErr)

			assert.Equal(t, tt.wantStatus, w.Code)
			assert.Equal(t, tt.want, body)
			assert.Equal(t, tt.wantErr, bodyErr)
		})
	}
}
