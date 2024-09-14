package controller

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/viniosilva/ipanemaboxapi/internal/controller/presenter"
)

type HealthCheckController struct{}

func NewHealthCheckController() *HealthCheckController {
	return &HealthCheckController{}
}

// HealthCheckController godoc
// @Summary      Health check API
// @Description  Verify status application
// @Tags         health
// @Accept       json
// @Produce      json
// @Success      200  {object}  presenter.HealthCheckRes
// @Router       /api/healthcheck [get]
func (c *HealthCheckController) Check(ctx *gin.Context) {
	ctx.JSON(http.StatusOK, presenter.HealthCheckRes{
		Status: presenter.HealthCheckStatusUp,
	})
}
