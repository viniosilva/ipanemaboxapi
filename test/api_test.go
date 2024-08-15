package test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/viniosilva/ipanemaboxapi/internal/factory"
)

func TestApi(t *testing.T) {
	r := configure()

	w := request(r, http.MethodGet, "/api/healthcheck")
	assert.Equal(t, http.StatusOK, w.Code)
}

func configure() *gin.Engine {
	f := factory.Build()
	r := gin.Default()
	r.GET("/api/healthcheck", f.HealthCheckController.Check)

	return r
}

func request(r *gin.Engine, method, url string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(method, url, nil)
	r.ServeHTTP(w, req)

	return w
}
