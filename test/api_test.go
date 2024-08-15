package test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/viniosilva/ipanemaboxapi/internal/factory"
)

func TestApi(t *testing.T) {
	r := configure()

	w := request(r, http.MethodGet, "/api/healthcheck", "")
	assert.Equal(t, http.StatusOK, w.Code)

	payload := `{"name":"Testing"}`
	w = request(r, http.MethodPost, "/api/v1/customers", payload)
	assert.Equal(t, http.StatusCreated, w.Code)
}

func configure() *gin.Engine {
	f := factory.Build()
	r := gin.Default()
	r.GET("/api/healthcheck", f.HealthCheckController.Check)
	r.POST("/api/v1/customers", f.CustomerController.Create)

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
