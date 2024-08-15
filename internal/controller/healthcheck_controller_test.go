package controller

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/viniosilva/ipanemaboxapi/internal/controller/presenter"
)

func TestNewHealthCheckController(t *testing.T) {
	got := NewHealthCheckController()

	assert.NotNil(t, got)
}

func TestHealthCheckController_Check(t *testing.T) {
	tests := map[string]struct {
		wantStatus int
		want       presenter.HealthCheckRes
	}{
		"should be successful": {
			wantStatus: http.StatusOK,
			want:       presenter.HealthCheckRes{Status: presenter.HealthCheckStatusUp},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			controller := NewHealthCheckController()
			r := gin.Default()
			r.GET("/api/healthcheck", controller.Check)

			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodGet, "/api/healthcheck", nil)
			r.ServeHTTP(w, req)

			var body presenter.HealthCheckRes
			json.Unmarshal(w.Body.Bytes(), &body)

			assert.Equal(t, tt.wantStatus, w.Code)
			assert.Equal(t, tt.want, body)
		})
	}
}
