package controller

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/viniosilva/ipanemaboxapi/internal/controller/presenter"
	"github.com/viniosilva/ipanemaboxapi/internal/dto"
	"github.com/viniosilva/ipanemaboxapi/internal/exception"
	"github.com/viniosilva/ipanemaboxapi/internal/model"
)

type CustomerController struct {
	customerSvc CustomerService
}

type CustomerService interface {
	Create(ctx context.Context, customer dto.CreateCustomerDto) (*model.Customer, error)
	Find(ctx context.Context, id int64) (*model.Customer, error)
}

func NewCustomerController(customerSvc CustomerService) *CustomerController {
	return &CustomerController{
		customerSvc: customerSvc,
	}
}

func (c *CustomerController) Create(ctx *gin.Context) {
	var payload presenter.CustomerReq
	if err := ctx.BindJSON(&payload); err != nil {
		ctx.JSON(http.StatusBadRequest, presenter.ErrorRes{Message: err.Error()})
		return
	}

	res, err := c.customerSvc.Create(ctx, dto.CreateCustomerDto{
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

func (c *CustomerController) Find(ctx *gin.Context) {
	idParam := ctx.Param("id")
	id, err := strconv.ParseInt(idParam, 10, 64)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, presenter.ErrorRes{Message: "invalid ID"})
		return
	}

	res, err := c.customerSvc.Find(ctx, id)
	if err != nil {
		if e, ok := err.(*exception.NotFoundException); ok {
			ctx.JSON(http.StatusNotFound, presenter.ErrorRes{Message: e.Error()})
			return
		}

		slog.ErrorContext(ctx, err.Error())
		ctx.JSON(http.StatusInternalServerError, presenter.ErrorRes{Message: presenter.INTERNAL_SERVER_ERROR_MSG})
		return
	}

	ctx.JSON(http.StatusOK, presenter.CustomerRes{
		ID:   res.ID,
		Name: res.Name,
	})
}
