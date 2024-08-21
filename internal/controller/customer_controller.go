package controller

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/viniosilva/ipanemaboxapi/internal/controller/presenter"
	"github.com/viniosilva/ipanemaboxapi/internal/dto"
	"github.com/viniosilva/ipanemaboxapi/internal/model"
)

type CustomerController struct {
	customerSvc CustomerService
}

type CustomerService interface {
	Create(ctx context.Context, customer dto.CreateCustomerDto) (*model.Customer, error)
}

func NewCustomerController(customerSvc CustomerService) *CustomerController {
	return &CustomerController{
		customerSvc: customerSvc,
	}
}

func (impl *CustomerController) Create(ctx *gin.Context) {
	var payload presenter.CustomerReq
	if err := ctx.BindJSON(&payload); err != nil {
		ctx.JSON(http.StatusBadRequest, presenter.ErrorRes{Message: err.Error()})
		return
	}

	res, err := impl.customerSvc.Create(ctx, dto.CreateCustomerDto{
		Name: payload.Name,
	})
	if err != nil {
		slog.ErrorContext(ctx, err.Error())

		ctx.JSON(http.StatusInternalServerError, presenter.ErrorRes{Message: presenter.INTERNAL_SERVER_ERROR_MSG})
		return
	}

	ctx.JSON(http.StatusCreated, presenter.CustomerRes{
		ID:   res.ID,
		Name: res.Name,
	})
}
