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
	"github.com/viniosilva/ipanemaboxapi/internal/exception"
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
		"should create a customer successfully": {
			mock: func(customerSvc *mock.MockCustomerService) {
				customerSvc.EXPECT().
					Create(gomock.Any(), dto.CustomerDataDto{Name: "Testing"}).
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
					Create(gomock.Any(), dto.CustomerDataDto{Name: "Testing"}).
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

func TestCustomerController_Find(t *testing.T) {
	type args struct {
		id string
	}
	tests := map[string]struct {
		mock       func(customerSvc *mock.MockCustomerService)
		args       args
		wantStatus int
		want       presenter.CustomerRes
		wantErr    presenter.ErrorRes
	}{
		"should find customer successfully": {
			mock: func(customerSvc *mock.MockCustomerService) {
				customerSvc.EXPECT().Find(gomock.Any(), int64(1)).
					Return(&model.Customer{ID: 1, Name: "Testing"}, nil)
			},
			args: args{
				id: "1",
			},
			wantStatus: http.StatusOK,
			want:       presenter.CustomerRes{ID: 1, Name: "Testing"},
		},
		"should throw bad request when ID is invalid": {
			mock:       func(customerSvc *mock.MockCustomerService) {},
			args:       args{id: "one"},
			wantStatus: http.StatusBadRequest,
			wantErr:    presenter.ErrorRes{Message: "invalid ID"},
		},
		"should throw not found when customer doesn't exist": {
			mock: func(customerSvc *mock.MockCustomerService) {
				customerSvc.EXPECT().Find(gomock.Any(), int64(2)).
					Return(nil, exception.NewNotFoundException("customer not found by ID 2"))
			},
			args:       args{id: "2"},
			wantStatus: http.StatusNotFound,
			wantErr:    presenter.ErrorRes{Message: "customer not found by ID 2"},
		},
		"should throw internal server error": {
			mock: func(customerSvc *mock.MockCustomerService) {
				customerSvc.EXPECT().Find(gomock.Any(), int64(3)).
					Return(nil, fmt.Errorf("error"))
			},
			args: args{
				id: "3",
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
			r.GET("/api/v1/customers/:id", controller.Find)

			w := httptest.NewRecorder()
			url := fmt.Sprintf("/api/v1/customers/%s", tt.args.id)
			req, _ := http.NewRequest(http.MethodGet, url, nil)
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

func TestCustomerController_Update(t *testing.T) {
	type args struct {
		id      string
		payload string
	}
	tests := map[string]struct {
		mock       func(customerSvc *mock.MockCustomerService)
		args       args
		wantStatus int
		want       presenter.CustomerRes
		wantErr    presenter.ErrorRes
	}{
		"should update customer successfully": {
			mock: func(customerSvc *mock.MockCustomerService) {
				customerSvc.EXPECT().
					Update(gomock.Any(), int64(1), dto.CustomerDataDto{Name: "Testing"}).
					Return(&model.Customer{ID: 1, Name: "Testing"}, nil)
			},
			args: args{
				id:      "1",
				payload: `{"name":"Testing"}`,
			},
			wantStatus: http.StatusOK,
			want:       presenter.CustomerRes{ID: 1, Name: "Testing"},
		},
		"should throw bad request when ID is invalid": {
			mock: func(customerSvc *mock.MockCustomerService) {},
			args: args{
				id:      "one",
				payload: `{"name":"Testing"}`,
			},
			wantStatus: http.StatusBadRequest,
			wantErr:    presenter.ErrorRes{Message: "invalid ID"},
		},
		"should throw error when payload is empty": {
			mock: func(customerSvc *mock.MockCustomerService) {},
			args: args{
				id:      "1",
				payload: "{}",
			},
			wantStatus: http.StatusBadRequest,
			wantErr:    presenter.ErrorRes{Message: "Key: 'CustomerReq.Name' Error:Field validation for 'Name' failed on the 'required' tag"},
		},
		"should throw not found when customer doesn't exist": {
			mock: func(customerSvc *mock.MockCustomerService) {
				customerSvc.EXPECT().
					Update(gomock.Any(), int64(2), dto.CustomerDataDto{Name: "Testing"}).
					Return(nil, exception.NewNotFoundException("customer not found by ID 2"))
			},
			args: args{
				id:      "2",
				payload: `{"name":"Testing"}`,
			},
			wantStatus: http.StatusNotFound,
			wantErr:    presenter.ErrorRes{Message: "customer not found by ID 2"},
		},
		"should throw internal server error": {
			mock: func(customerSvc *mock.MockCustomerService) {
				customerSvc.EXPECT().
					Update(gomock.Any(), int64(3), dto.CustomerDataDto{Name: "Testing"}).
					Return(nil, fmt.Errorf("some internal error"))
			},
			args: args{
				id:      "3",
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
			r.PUT("/api/v1/customers/:id", controller.Update)

			w := httptest.NewRecorder()
			url := fmt.Sprintf("/api/v1/customers/%s", tt.args.id)
			req, _ := http.NewRequest(http.MethodPut, url, strings.NewReader(tt.args.payload))
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
