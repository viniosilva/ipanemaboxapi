package controller

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vinosilva/ipanemaboxapi/internal/config"
	"github.com/vinosilva/ipanemaboxapi/internal/controller/presenter"
	"github.com/vinosilva/ipanemaboxapi/internal/infra"
	"github.com/vinosilva/ipanemaboxapi/internal/model"
)

func TestApp(t *testing.T) {
	t.Run("test app", func(t *testing.T) {
		// setup
		time.Local = time.UTC
		infra.ConfigZapLooger()

		c, err := config.GetConfig("..")
		require.Nil(t, err)

		db, err := infra.MySQLConnect(c.MySQL.Username, c.MySQL.Password, c.MySQL.Host, c.MySQL.Port,
			c.MySQL.Database, c.MySQL.ConnMaxLifetime, c.MySQL.MaxOpenConns, c.MySQL.MaxIdleConns)
		require.Nil(t, err)

		dep := config.FactoryBuild(db)
		r := infra.GinSetup(c.Api.Host, c.Api.Port, infra.Zap, dep.HealthController, dep.CustomerController)

		// given
		createCustomerRequest := presenter.CustomerCreateRequest{
			FullName: "fullname",
			Email:    "email@email.com",
		}
		updateCustomerRequest := presenter.CustomerUpdateRequest{
			FullName: "updated fullname",
			Email:    "updatedemail@email.com",
		}

		// defers
		defer db.Exec("DELETE FROM customers")
		defer db.Exec("ALTER TABLE customers AUTO_INCREMENT = 1")

		// when
		getHealth(t, r)
		customer := postCustomers(t, r, createCustomerRequest)
		getCustomers(t, r, customer)

		updateCustomerRequest.UpdatedAt = customer.UpdatedAt
		customer = updateCustomer(t, r, customer.ID, updateCustomerRequest)
		getCustomerByID(t, r, customer)
	})
}

func getHealth(t *testing.T, r *gin.Engine) {
	// given
	wantCode := http.StatusOK
	wantBody := presenter.HealthCheckResponse{
		Status: model.HealthCheckStatusUp,
	}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/healthcheck", nil)

	var got presenter.HealthCheckResponse

	// when
	r.ServeHTTP(w, req)

	json.Unmarshal(w.Body.Bytes(), &got)

	// then
	assert.Equal(t, wantCode, w.Code)
	assert.Equal(t, wantBody, got)
}

func postCustomers(t *testing.T, r *gin.Engine, data presenter.CustomerCreateRequest) presenter.CustomerResponseData {
	// given
	wantCode := http.StatusCreated
	wantBody := presenter.CustomerResponseData{
		FullName: data.FullName,
		Email:    data.Email,
	}

	body, _ := json.Marshal(data)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/customers", bytes.NewReader(body))

	var got presenter.CustomerResponseData

	// when
	r.ServeHTTP(w, req)

	json.Unmarshal(w.Body.Bytes(), &got)

	wantBody.ID = got.ID
	wantBody.CreatedAt = got.CreatedAt
	wantBody.UpdatedAt = got.UpdatedAt

	// then
	assert.Equal(t, wantCode, w.Code)
	assert.Equal(t, wantBody, got)

	return got
}

func getCustomers(t *testing.T, r *gin.Engine, wantData ...presenter.CustomerResponseData) {
	// given
	wantCode := http.StatusOK
	wantBody := presenter.CustomersResponse{Data: wantData}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/customers", nil)

	var got presenter.CustomersResponse

	// when
	r.ServeHTTP(w, req)

	json.Unmarshal(w.Body.Bytes(), &got)
	for i := range got.Data {
		wantBody.Data[i].ID = got.Data[i].ID
		wantBody.Data[i].CreatedAt = got.Data[i].CreatedAt
		wantBody.Data[i].UpdatedAt = got.Data[i].UpdatedAt
	}

	// then
	assert.Equal(t, wantCode, w.Code)
	assert.Equal(t, wantBody, got)
}

func updateCustomer(t *testing.T, r *gin.Engine, customerID int64, data presenter.CustomerUpdateRequest) presenter.CustomerResponseData {
	// given
	wantCode := http.StatusOK
	wantBody := presenter.CustomerResponseData{
		ID:       customerID,
		FullName: data.FullName,
		Email:    data.Email,
	}

	body, _ := json.Marshal(data)

	w := httptest.NewRecorder()
	url := fmt.Sprintf("/api/v1/customers/%d", customerID)
	req, _ := http.NewRequest(http.MethodPatch, url, bytes.NewReader(body))
	var got presenter.CustomerResponseData

	// when
	r.ServeHTTP(w, req)

	json.Unmarshal(w.Body.Bytes(), &got)
	wantBody.CreatedAt = got.CreatedAt
	wantBody.UpdatedAt = got.UpdatedAt

	// then
	assert.Equal(t, wantCode, w.Code)
	assert.Equal(t, wantBody, got)

	return got
}

func getCustomerByID(t *testing.T, r *gin.Engine, wantBody presenter.CustomerResponseData) {
	// given
	wantCode := http.StatusOK

	w := httptest.NewRecorder()
	url := fmt.Sprintf("/api/v1/customers/%d", wantBody.ID)
	req, _ := http.NewRequest(http.MethodGet, url, nil)

	var got presenter.CustomerResponseData

	// when
	r.ServeHTTP(w, req)

	json.Unmarshal(w.Body.Bytes(), &got)

	// then
	assert.Equal(t, wantCode, w.Code)
	assert.Equal(t, wantBody, got)
}
