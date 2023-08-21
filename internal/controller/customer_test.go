package controller

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	parserUrl "net/url"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/vinosilva/ipanemaboxapi/internal/controller/presenter"
	"github.com/vinosilva/ipanemaboxapi/internal/dto"
	"github.com/vinosilva/ipanemaboxapi/internal/exception"
	"github.com/vinosilva/ipanemaboxapi/internal/model"
	"github.com/vinosilva/ipanemaboxapi/mock"
)

func TestCustomerController_Create(t *testing.T) {
	tm := time.Now()

	tests := map[string]struct {
		mock        func(customerService *mock.MockCustomerService)
		body        presenter.CustomerCreateRequest
		wantCode    int
		wantBody    presenter.CustomerResponseData
		wantBodyErr presenter.ErrorResponse
	}{
		"should be success": {
			mock: func(customerService *mock.MockCustomerService) {
				customerService.EXPECT().Create(gomock.Any(), gomock.Any()).Return(&model.Customer{
					ID:        1,
					CreatedAt: &tm,
					UpdatedAt: &tm,
					FullName:  "full name",
					Email:     "email@email.com",
				}, nil)
			},
			body: presenter.CustomerCreateRequest{
				FullName: "full name",
				Email:    "email@email.com",
			},
			wantCode: http.StatusCreated,
			wantBody: presenter.CustomerResponseData{
				ID:        1,
				CreatedAt: tm.Format(time.DateTime),
				UpdatedAt: tm.Format(time.DateTime),
				FullName:  "full name",
				Email:     "email@email.com",
			},
		},
		"should throw validation exception": {
			mock: func(customerService *mock.MockCustomerService) {
				customerService.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil, exception.NewValidationException(validator.ValidationErrors{
					&mock.FieldError{Itag: "error 1", Ins: "error 1"},
					&mock.FieldError{Itag: "error 2", Ins: "error 2"},
				}))
			},
			body:     presenter.CustomerCreateRequest{},
			wantCode: http.StatusBadRequest,
			wantBodyErr: presenter.ErrorResponse{
				Error: exception.ValidationExceptionName,
				Messages: []string{
					"Key: 'error 1' Error:Field validation for '' failed on the 'error 1' tag",
					"Key: 'error 2' Error:Field validation for '' failed on the 'error 2' tag",
				},
			},
		},
		"should throw internal server error": {
			mock: func(customerService *mock.MockCustomerService) {
				customerService.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil, fmt.Errorf("error"))
			},
			body:        presenter.CustomerCreateRequest{},
			wantCode:    http.StatusInternalServerError,
			wantBodyErr: presenter.ErrorResponse{Error: http.StatusText(http.StatusInternalServerError)},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			// setup
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			customerServiceMock := mock.NewMockCustomerService(ctrl)
			tt.mock(customerServiceMock)

			r := gin.Default()
			customerController := NewCustomer(customerServiceMock)

			r.POST("/api/v1/customers", customerController.Create)

			var got presenter.CustomerResponseData
			var gotErr presenter.ErrorResponse

			// given
			body, _ := json.Marshal(tt.body)
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodPost, "/api/v1/customers", bytes.NewReader(body))

			// when
			r.ServeHTTP(w, req)

			errBodyErr := json.Unmarshal(w.Body.Bytes(), &gotErr)
			json.Unmarshal(w.Body.Bytes(), &got)

			// then
			assert.Equal(t, tt.wantCode, w.Code)

			if errBodyErr == nil {
				assert.Equal(t, tt.wantBodyErr, gotErr)
				return
			}

			assert.Equal(t, tt.wantBody, got)
		})
	}
}

func TestCustomerController_FindAll(t *testing.T) {
	tm := time.Now()

	tests := map[string]struct {
		mock        func(customerService *mock.MockCustomerService)
		queryPage   string
		querySize   string
		wantCode    int
		wantBody    presenter.CustomersResponse
		wantBodyErr presenter.ErrorResponse
	}{
		"should return customers": {
			mock: func(customerService *mock.MockCustomerService) {
				customerService.EXPECT().FindAll(gomock.Any(), dto.CustomerFindAllData{Page: 1, Size: 1}).Return(&dto.CustomersResult{
					Data: []model.Customer{
						{
							ID:        1,
							CreatedAt: &tm,
							UpdatedAt: &tm,
							FullName:  "full name",
							Email:     "email@email.com",
						},
					},
				}, nil)
			},
			queryPage: "1",
			querySize: "1",
			wantCode:  http.StatusOK,
			wantBody: presenter.CustomersResponse{
				Data: []presenter.CustomerResponseData{
					{
						ID:        1,
						CreatedAt: tm.Format(time.DateTime),
						UpdatedAt: tm.Format(time.DateTime),
						FullName:  "full name",
						Email:     "email@email.com",
					},
				},
			},
		},
		"should throw validation exception": {
			mock: func(customerService *mock.MockCustomerService) {
				customerService.EXPECT().FindAll(gomock.Any(), dto.CustomerFindAllData{Page: 1, Size: 10}).Return(nil, exception.NewValidationException(fmt.Errorf("error")))
			},
			wantCode: http.StatusBadRequest,
			wantBodyErr: presenter.ErrorResponse{
				Error: http.StatusText(http.StatusBadRequest),
			},
		},
		"should throw internal server error": {
			mock: func(customerService *mock.MockCustomerService) {
				customerService.EXPECT().FindAll(gomock.Any(), dto.CustomerFindAllData{Page: 2, Size: 10}).Return(nil, fmt.Errorf("error"))
			},
			queryPage:   "2",
			querySize:   "10",
			wantCode:    http.StatusInternalServerError,
			wantBodyErr: presenter.ErrorResponse{Error: http.StatusText(http.StatusInternalServerError)},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			// setup
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			customerServiceMock := mock.NewMockCustomerService(ctrl)
			tt.mock(customerServiceMock)

			r := gin.Default()
			customerController := NewCustomer(customerServiceMock)

			r.GET("/api/v1/customers", customerController.FindAll)

			url := parserUrl.URL{Path: "/api/v1/customers"}
			q := url.Query()
			q.Set("page", tt.queryPage)
			q.Set("size", tt.querySize)
			url.RawQuery = q.Encode()

			var got presenter.CustomerResponseData
			var gotErr presenter.ErrorResponse

			// given
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodGet, url.String(), nil)

			// when
			r.ServeHTTP(w, req)

			errBodyErr := json.Unmarshal(w.Body.Bytes(), &gotErr)
			json.Unmarshal(w.Body.Bytes(), &got)

			// then
			assert.Equal(t, tt.wantCode, w.Code)

			if errBodyErr == nil {
				assert.Equal(t, tt.wantBodyErr, gotErr)
				return
			}

			assert.Equal(t, tt.wantBody, got)
		})
	}
}

func TestCustomerController_FindByID(t *testing.T) {
	tm := time.Now()

	tests := map[string]struct {
		mock        func(customerService *mock.MockCustomerService)
		customerID  string
		wantCode    int
		wantBody    presenter.CustomerResponseData
		wantBodyErr presenter.ErrorResponse
	}{
		"should return customer": {
			mock: func(customerService *mock.MockCustomerService) {
				customerService.EXPECT().FindByID(gomock.Any(), int64(1)).Return(&model.Customer{
					ID:        1,
					CreatedAt: &tm,
					UpdatedAt: &tm,
					FullName:  "full name",
					Email:     "email@email.com",
				}, nil)
			},
			customerID: "1",
			wantCode:   http.StatusOK,
			wantBody: presenter.CustomerResponseData{
				ID:        1,
				CreatedAt: tm.Format(time.DateTime),
				UpdatedAt: tm.Format(time.DateTime),
				FullName:  "full name",
				Email:     "email@email.com",
			},
		},
		"should throw bad request error": {
			mock:       func(customerService *mock.MockCustomerService) {},
			customerID: "one",
			wantCode:   http.StatusBadRequest,
			wantBodyErr: presenter.ErrorResponse{
				Error:   http.StatusText(http.StatusBadRequest),
				Message: "invalid customer id",
			},
		},
		"should throw not found error": {
			mock: func(customerService *mock.MockCustomerService) {
				customerService.EXPECT().FindByID(gomock.Any(), int64(1)).Return(nil, exception.NewNotFoundException("customer"))
			},
			customerID: "1",
			wantCode:   http.StatusNotFound,
			wantBodyErr: presenter.ErrorResponse{
				Error:   http.StatusText(http.StatusNotFound),
				Message: "customer not found",
			},
		},
		"should throw internal server error": {
			mock: func(customerService *mock.MockCustomerService) {
				customerService.EXPECT().FindByID(gomock.Any(), int64(1)).Return(nil, fmt.Errorf("error"))
			},
			customerID:  "1",
			wantCode:    http.StatusInternalServerError,
			wantBodyErr: presenter.ErrorResponse{Error: http.StatusText(http.StatusInternalServerError)},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			// setup
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			customerServiceMock := mock.NewMockCustomerService(ctrl)
			tt.mock(customerServiceMock)

			r := gin.Default()
			customerController := NewCustomer(customerServiceMock)

			r.GET("/api/v1/customers/:customer_id", customerController.FindByID)

			var got presenter.CustomerResponseData
			var gotErr presenter.ErrorResponse

			// given
			url := fmt.Sprintf("/api/v1/customers/%s", tt.customerID)
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodGet, url, nil)

			// when
			r.ServeHTTP(w, req)

			errBodyErr := json.Unmarshal(w.Body.Bytes(), &gotErr)
			json.Unmarshal(w.Body.Bytes(), &got)

			// then
			assert.Equal(t, tt.wantCode, w.Code)

			if errBodyErr == nil {
				assert.Equal(t, tt.wantBodyErr, gotErr)
				return
			}

			assert.Equal(t, tt.wantBody, got)
		})
	}
}

func TestCustomerController_Update(t *testing.T) {
	tm := time.Now()

	tests := map[string]struct {
		mock        func(customerService *mock.MockCustomerService)
		customerID  string
		body        presenter.CustomerUpdateRequest
		wantCode    int
		wantBody    presenter.CustomerResponseData
		wantBodyErr presenter.ErrorResponse
	}{
		"should be success": {
			mock: func(customerService *mock.MockCustomerService) {
				customerService.EXPECT().Update(gomock.Any(), gomock.Any()).Return(&model.Customer{
					ID:        1,
					CreatedAt: &tm,
					UpdatedAt: &tm,
					FullName:  "updated full name",
					Email:     "updatedemail@email.com",
				}, nil)
			},
			customerID: "1",
			body: presenter.CustomerUpdateRequest{
				FullName:  "updated full name",
				Email:     "updatedemail@email.com",
				UpdatedAt: tm.Format(time.DateTime),
			},
			wantCode: http.StatusOK,
			wantBody: presenter.CustomerResponseData{
				ID:        1,
				CreatedAt: tm.Format(time.DateTime),
				UpdatedAt: tm.Format(time.DateTime),
				FullName:  "updated full name",
				Email:     "updatedemail@email.com",
			},
		},
		"should throw bad request error when customerID is invalid": {
			mock:       func(customerService *mock.MockCustomerService) {},
			customerID: "one",
			wantCode:   http.StatusBadRequest,
			wantBodyErr: presenter.ErrorResponse{
				Error:   http.StatusText(http.StatusBadRequest),
				Message: "invalid customer id",
			},
		},
		"should throw bad request error when updatedAt is invalid": {
			mock:       func(customerService *mock.MockCustomerService) {},
			customerID: "1",
			body: presenter.CustomerUpdateRequest{
				FullName:  "updated full name",
				Email:     "updatedemail@email.com",
				UpdatedAt: "invalid_date",
			},
			wantCode: http.StatusBadRequest,
			wantBodyErr: presenter.ErrorResponse{
				Error:   http.StatusText(http.StatusBadRequest),
				Message: "invalid updated_at",
			},
		},
		"should throw validation exception": {
			mock: func(customerService *mock.MockCustomerService) {
				customerService.EXPECT().Update(gomock.Any(), gomock.Any()).Return(nil, exception.NewValidationException(fmt.Errorf("error")))
			},
			customerID: "1",
			body: presenter.CustomerUpdateRequest{
				FullName:  "updated full name",
				Email:     "invalid email",
				UpdatedAt: tm.Format(time.DateTime),
			},
			wantCode: http.StatusBadRequest,
			wantBodyErr: presenter.ErrorResponse{
				Error: http.StatusText(http.StatusBadRequest),
			},
		},
		"should throw not found exception": {
			mock: func(customerService *mock.MockCustomerService) {
				customerService.EXPECT().Update(gomock.Any(), gomock.Any()).Return(nil, exception.NewNotFoundException("customer"))
			},
			customerID: "1",
			body: presenter.CustomerUpdateRequest{
				FullName:  "updated full name",
				Email:     "updatedemail@email.com",
				UpdatedAt: tm.Format(time.DateTime),
			},
			wantCode: http.StatusNotFound,
			wantBodyErr: presenter.ErrorResponse{
				Error:   http.StatusText(http.StatusNotFound),
				Message: "customer not found",
			},
		},
		"should throw internal server error": {
			mock: func(customerService *mock.MockCustomerService) {
				customerService.EXPECT().Update(gomock.Any(), gomock.Any()).Return(nil, fmt.Errorf("error"))
			},
			customerID: "1",
			body: presenter.CustomerUpdateRequest{
				FullName:  "updated full name",
				Email:     "updatedemail@email.com",
				UpdatedAt: tm.Format(time.DateTime),
			},
			wantCode:    http.StatusInternalServerError,
			wantBodyErr: presenter.ErrorResponse{Error: http.StatusText(http.StatusInternalServerError)},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			// setup
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			customerServiceMock := mock.NewMockCustomerService(ctrl)
			tt.mock(customerServiceMock)

			r := gin.Default()
			customerController := NewCustomer(customerServiceMock)

			r.PATCH("/api/v1/customers/:customer_id", customerController.Update)

			var got presenter.CustomerResponseData
			var gotErr presenter.ErrorResponse

			// given
			body, _ := json.Marshal(tt.body)
			url := fmt.Sprintf("/api/v1/customers/%s", tt.customerID)
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodPatch, url, bytes.NewReader(body))

			// when
			r.ServeHTTP(w, req)

			json.Unmarshal(w.Body.Bytes(), &got)
			errBodyErr := json.Unmarshal(w.Body.Bytes(), &gotErr)

			// then
			assert.Equal(t, tt.wantCode, w.Code)

			if errBodyErr == nil {
				assert.Equal(t, tt.wantBodyErr, gotErr)
				return
			}

			assert.Equal(t, tt.wantBody, got)
		})
	}
}
