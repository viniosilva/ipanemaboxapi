package controller

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/viniosilva/ipanemaboxapi/internal/controller/presenter"
)

type CustomerController struct{}

func NewCustomerController() *CustomerController {
	return &CustomerController{}
}

func (impl *CustomerController) Create(ctx *gin.Context) {
	var payload presenter.CustomerReq
	if err := ctx.BindJSON(&payload); err != nil {
		ctx.JSON(http.StatusBadRequest, presenter.ErrorRes{Message: err.Error()})
		return
	}

	ctx.JSON(http.StatusCreated, presenter.CustomerRes{
		ID:   1,
		Name: "Testing",
	})
}
