package controller

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/vinosilva/ipanemaboxapi/internal/controller/presenter"
	"github.com/vinosilva/ipanemaboxapi/internal/model"
	"github.com/vinosilva/ipanemaboxapi/mock"
)

func TestHealthController_Check(t *testing.T) {
	tests := map[string]struct {
		mock     func(healthService *mock.MockHealthService)
		wantCode int
		wantBody presenter.HealthCheckResponse
	}{
		"should be success": {
			mock: func(healthService *mock.MockHealthService) {
				healthService.EXPECT().Check(gomock.Any()).Return(nil)
			},
			wantCode: http.StatusOK,
			wantBody: presenter.HealthCheckResponse{Status: model.HealthCheckStatusUp},
		},
		"should throw error": {
			mock: func(healthService *mock.MockHealthService) {
				healthService.EXPECT().Check(gomock.Any()).Return(fmt.Errorf("error"))
			},
			wantCode: http.StatusInternalServerError,
			wantBody: presenter.HealthCheckResponse{Status: model.HealthCheckStatusDown},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			// setup
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			healthServiceMock := mock.NewMockHealthService(ctrl)
			tt.mock(healthServiceMock)

			r := gin.Default()
			healthController := NewHealth(healthServiceMock)

			r.GET("/api/healthcheck", healthController.Check)

			var got presenter.HealthCheckResponse

			// given
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/api/healthcheck", nil)

			// when
			r.ServeHTTP(w, req)

			json.Unmarshal(w.Body.Bytes(), &got)

			// then
			assert.Equal(t, tt.wantCode, w.Code)
			assert.Equal(t, tt.wantBody, got)
		})
	}
}
