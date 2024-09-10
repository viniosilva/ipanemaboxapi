package test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/viniosilva/ipanemaboxapi/internal/factory"
	"github.com/viniosilva/ipanemaboxapi/internal/utils/config"
	"github.com/viniosilva/ipanemaboxapi/pkg/postgres"
)

func TestApi(t *testing.T) {
	r := configure(t)

	t.Run("should ping healthcheck", func(tt *testing.T) {
		w := request(r, http.MethodGet, "/api/healthcheck", "")
		assert.Equal(tt, http.StatusOK, w.Code)
	})

	t.Run("should create a customer", func(tt *testing.T) {
		payload := `{"name":"Testing"}`
		w := request(r, http.MethodPost, "/api/v1/customers", payload)
		assert.Equal(t, http.StatusCreated, w.Code)
	})
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
