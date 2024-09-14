package test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/viniosilva/ipanemaboxapi/internal/controller/presenter"
	"github.com/viniosilva/ipanemaboxapi/internal/factory"
	"github.com/viniosilva/ipanemaboxapi/internal/utils/config"
	"github.com/viniosilva/ipanemaboxapi/pkg/postgres"
)

func TestApi(t *testing.T) {
	var customer presenter.CustomerRes
	r := configure(t)

	// should ping healthcheck
	w := request(r, http.MethodGet, "/api/healthcheck", "")
	assert.Equal(t, http.StatusOK, w.Code)

	// should create a customer
	payload := `{"name":"Testing"}`
	w = request(r, http.MethodPost, "/api/v1/customers", payload)
	assert.Equal(t, http.StatusCreated, w.Code)

	err := json.Unmarshal(w.Body.Bytes(), &customer)
	require.NoError(t, err)

	// should find customer
	url := fmt.Sprintf("/api/v1/customers/%d", customer.ID)
	w = request(r, http.MethodGet, url, "")
	assert.Equal(t, http.StatusOK, w.Code)

	// should update customer
	payload = `{"name":"Testing Updated"}`
	w = request(r, http.MethodPut, url, payload)
	assert.Equal(t, http.StatusOK, w.Code)

	// should delete customer
	w = request(r, http.MethodDelete, url, "")
	assert.Equal(t, http.StatusNoContent, w.Code)
}

func configure(t *testing.T) *gin.Engine {
	cfg, err := config.ViperConfigure(".")
	require.NoError(t, err)

	db, err := postgres.Connect(cfg.DB.Host, cfg.DB.Port, cfg.DB.DbName, cfg.DB.Username, cfg.DB.Password, cfg.DB.Ssl)
	require.NoError(t, err)

	f := factory.Build(db)
	r := gin.Default()
	r.GET("/api/healthcheck", f.HealthCheckController.Check)
	r.POST("/api/v1/customers", f.CustomerController.Create)
	r.GET("/api/v1/customers/:id", f.CustomerController.Find)
	r.PUT("/api/v1/customers/:id", f.CustomerController.Update)
	r.DELETE("/api/v1/customers/:id", f.CustomerController.Delete)

	return r
}

func request(r *gin.Engine, method, url, payload string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()

	var body io.Reader
	if payload != "" {
		body = strings.NewReader(payload)
	}

	req, _ := http.NewRequest(method, url, body)
	r.ServeHTTP(w, req)

	return w
}
