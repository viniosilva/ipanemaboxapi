package controller

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	_url "net/url"
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

func TestCustomerController_List(t *testing.T) {
	type args struct {
		page  string
		limit string
	}
	tests := map[string]struct {
		mock       func(customerSvc *mock.MockCustomerService)
		args       args
		wantStatus int
		want       presenter.CustomersListRes
		wantErr    presenter.ErrorRes
	}{
		"should list 2 of 2 customers successfully when page and limit are default": {
			mock: func(customerSvc *mock.MockCustomerService) {
				customerSvc.EXPECT().List(gomock.Any(), 1, 10).Return(&dto.CustomersList{
					Meta: dto.MetadataPage{
						TotalCount:  2,
						TotalPages:  1,
						CurrentPage: 1,
						PageSize:    10,
					},
					Data: []model.Customer{
						{ID: 1, Name: "Customer 1"},
						{ID: 2, Name: "Customer 2"},
					},
				}, nil)
			},
			args:       args{},
			wantStatus: http.StatusOK,
			want: presenter.CustomersListRes{
				Metadata: presenter.MetadataPage{
					TotalCount:  2,
					TotalPages:  1,
					CurrentPage: 1,
					PageSize:    10,
				},
				Data: []presenter.CustomerRes{
					{ID: 1, Name: "Customer 1"},
					{ID: 2, Name: "Customer 2"},
				},
			},
		},
		"should list 2 of 4 customers successfully when page is 2 and limit is 2": {
			mock: func(customerSvc *mock.MockCustomerService) {
				customerSvc.EXPECT().List(gomock.Any(), 2, 2).Return(&dto.CustomersList{
					Meta: dto.MetadataPage{
						TotalCount:  4,
						TotalPages:  2,
						CurrentPage: 2,
						PageSize:    2,
					},
					Data: []model.Customer{
						{ID: 3, Name: "Customer 3"},
						{ID: 4, Name: "Customer 4"},
					},
				}, nil)
			},
			args: args{
				page:  "2",
				limit: "2",
			},
			wantStatus: http.StatusOK,
			want: presenter.CustomersListRes{
				Metadata: presenter.MetadataPage{
					TotalCount:  4,
					TotalPages:  2,
					CurrentPage: 2,
					PageSize:    2,
				},
				Data: []presenter.CustomerRes{
					{ID: 3, Name: "Customer 3"},
					{ID: 4, Name: "Customer 4"},
				},
			},
		},
		"should list empty customers list when page is 2 and totalCount is 10": {
			mock: func(customerSvc *mock.MockCustomerService) {
				customerSvc.EXPECT().List(gomock.Any(), 2, 10).Return(&dto.CustomersList{
					Meta: dto.MetadataPage{
						TotalCount:  10,
						TotalPages:  1,
						CurrentPage: 2,
						PageSize:    0,
					},
					Data: []model.Customer{},
				}, nil)
			},
			args: args{
				page: "2",
			},
			wantStatus: http.StatusOK,
			want: presenter.CustomersListRes{
				Metadata: presenter.MetadataPage{
					TotalCount:  10,
					TotalPages:  1,
					CurrentPage: 2,
					PageSize:    0,
				},
				Data: []presenter.CustomerRes{},
			},
		},
		"should throw bad request when page is invalid number": {
			mock: func(customerSvc *mock.MockCustomerService) {},
			args: args{
				page: "0", // Invalid page
			},
			wantStatus: http.StatusBadRequest,
			wantErr:    presenter.ErrorRes{Message: "invalid page"},
		},
		"should throw bad request when page is invalid value": {
			mock: func(customerSvc *mock.MockCustomerService) {},
			args: args{
				page: "invalid",
			},
			wantStatus: http.StatusBadRequest,
			wantErr:    presenter.ErrorRes{Message: "invalid page"},
		},
		"should throw bad request when limit is invalid number": {
			mock: func(customerSvc *mock.MockCustomerService) {},
			args: args{
				limit: "0", // Invalid limit
			},
			wantStatus: http.StatusBadRequest,
			wantErr:    presenter.ErrorRes{Message: "invalid limit"},
		},
		"should throw bad request when limit is invalid value": {
			mock: func(customerSvc *mock.MockCustomerService) {},
			args: args{
				limit: "invalid",
			},
			wantStatus: http.StatusBadRequest,
			wantErr:    presenter.ErrorRes{Message: "invalid limit"},
		},
		"should throw internal server error": {
			mock: func(customerSvc *mock.MockCustomerService) {
				customerSvc.EXPECT().List(gomock.Any(), 1, 10).Return(nil, errors.New("error"))
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
			r.GET("/api/v1/customers", controller.List)

			w := httptest.NewRecorder()
			url := _url.URL{Path: "/api/v1/customers"}
			query := url.Query()
			if tt.args.page != "" {
				query.Set("page", tt.args.page)
			}
			if tt.args.limit != "" {
				query.Set("limit", tt.args.limit)
			}
			url.RawQuery = query.Encode()

			req, _ := http.NewRequest(http.MethodGet, url.String(), nil)
			r.ServeHTTP(w, req)

			var body presenter.CustomersListRes
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

func TestCustomerController_Delete(t *testing.T) {
	type args struct {
		id string
	}
	tests := map[string]struct {
		mock       func(customerSvc *mock.MockCustomerService)
		args       args
		wantStatus int
		wantErr    presenter.ErrorRes
	}{
		"should find customer successfully": {
			mock: func(customerSvc *mock.MockCustomerService) {
				customerSvc.EXPECT().Delete(gomock.Any(), int64(1)).
					Return(nil)
			},
			args: args{
				id: "1",
			},
			wantStatus: http.StatusNoContent,
		},
		"should throw bad request when ID is invalid": {
			mock:       func(customerSvc *mock.MockCustomerService) {},
			args:       args{id: "one"},
			wantStatus: http.StatusBadRequest,
			wantErr:    presenter.ErrorRes{Message: "invalid ID"},
		},
		"should throw internal server error": {
			mock: func(customerSvc *mock.MockCustomerService) {
				customerSvc.EXPECT().Delete(gomock.Any(), int64(1)).
					Return(fmt.Errorf("error"))
			},
			args: args{
				id: "1",
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
			r.DELETE("/api/v1/customers/:id", controller.Delete)

			w := httptest.NewRecorder()
			url := fmt.Sprintf("/api/v1/customers/%s", tt.args.id)
			req, _ := http.NewRequest(http.MethodDelete, url, nil)
			r.ServeHTTP(w, req)

			var bodyErr presenter.ErrorRes
			json.Unmarshal(w.Body.Bytes(), &bodyErr)

			assert.Equal(t, tt.wantStatus, w.Code)
			assert.Equal(t, tt.wantErr, bodyErr)
		})
	}
}
