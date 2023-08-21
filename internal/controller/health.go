package controller

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vinosilva/ipanemaboxapi/internal/controller/presenter"
	"github.com/vinosilva/ipanemaboxapi/internal/model"
)

type HealthController struct {
	healthService HealthService
}

func NewHealth(healthService HealthService) *HealthController {
	return &HealthController{
		healthService: healthService,
	}
}

// HealthCheck godoc
// @Summary healthcheck
// @Schemes
// @Tags health
// @Accept json
// @Produce json
// @Success 200 {object} presenter.HealthCheckResponse
// @Success 500 {object} presenter.HealthCheckResponse
// @Router /healthcheck [get]
func (impl *HealthController) Check(ctx *gin.Context) {
	code := http.StatusOK
	res := &presenter.HealthCheckResponse{
		Status: model.HealthCheckStatusUp,
	}

	if err := impl.healthService.Check(ctx); err != nil {
		code = http.StatusInternalServerError
		res.Status = model.HealthCheckStatusDown
	}

	ctx.JSON(code, res)
}
