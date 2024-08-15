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

func (impl *HealthCheckController) Check(ctx *gin.Context) {
	ctx.JSON(http.StatusOK, presenter.HealthCheckRes{
		Status: presenter.HealthCheckStatusUp,
	})
}
