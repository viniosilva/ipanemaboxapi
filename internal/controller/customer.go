package controller

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/vinosilva/ipanemaboxapi/internal/controller/presenter"
	"github.com/vinosilva/ipanemaboxapi/internal/dto"
	"github.com/vinosilva/ipanemaboxapi/internal/exception"
	"github.com/vinosilva/ipanemaboxapi/internal/model"
)

type CustomerController struct {
	customerService CustomerService
}

func NewCustomer(customerService CustomerService) *CustomerController {
	return &CustomerController{
		customerService: customerService,
	}
}

// Customer godoc
// @Summary create customer
// @Schemes
// @Tags customers
// @Accept json
// @Produce json
// @Param customer body presenter.CustomerDataRequest true "Customer"
// @Success 201 {object} presenter.CustomerResponseData
// @Success 400 {object} presenter.ErrorResponse
// @Success 500 {object} presenter.ErrorResponse
// @Router /v1/customers [post]
func (impl *CustomerController) Create(ctx *gin.Context) {
	var req presenter.CustomerCreateRequest
	ctx.BindJSON(&req)

	data := dto.CustomerCreateData{
		FullName: req.FullName,
		Email:    req.Email,
	}

	res, err := impl.customerService.Create(ctx, data)
	if err != nil {
		if e, ok := err.(*exception.ValidationException); ok {
			ctx.JSON(http.StatusBadRequest, presenter.ErrorResponse{Error: e.Name, Messages: e.Errors})
			return
		}

		ctx.JSON(http.StatusInternalServerError, presenter.ErrorResponse{Error: http.StatusText(http.StatusInternalServerError)})
		return
	}

	ctx.JSON(http.StatusCreated, impl.parse(res))
}

// Customer godoc
// @Summary find customers
// @Schemes
// @Tags customers
// @Accept json
// @Produce json
// @Param page query int false "page"
// @Param size query int false "size"
// @Success 200 {object} presenter.CustomersResponse
// @Success 400 {object} presenter.ErrorResponse
// @Success 500 {object} presenter.ErrorResponse
// @Router /v1/customers [get]
func (impl *CustomerController) FindAll(ctx *gin.Context) {
	page, err := strconv.Atoi(ctx.Query("page"))
	if err != nil {
		page = 1
	}
	size, err := strconv.Atoi(ctx.Query("size"))
	if err != nil {
		size = 10
	}

	data := dto.CustomerFindAllData{
		Page: page,
		Size: size,
	}

	res, err := impl.customerService.FindAll(ctx, data)
	if err != nil {
		if e, ok := err.(*exception.ValidationException); ok {
			ctx.JSON(http.StatusBadRequest, presenter.ErrorResponse{
				Error:    http.StatusText(http.StatusBadRequest),
				Messages: e.Errors,
			})
			return
		}

		ctx.JSON(http.StatusInternalServerError, presenter.ErrorResponse{Error: http.StatusText(http.StatusInternalServerError)})
		return
	}

	customers := make([]presenter.CustomerResponseData, 0)
	for _, c := range res.Data {
		customers = append(customers, impl.parse(&c))
	}

	ctx.JSON(http.StatusOK, presenter.CustomersResponse{Data: customers})
}

// Customer godoc
// @Summary find customer by id
// @Schemes
// @Tags customers
// @Accept json
// @Produce json
// @Param customer_id path int true "customer_id"
// @Success 200 {object} presenter.CustomerResponseData
// @Success 400 {object} presenter.ErrorResponse
// @Success 404 {object} presenter.ErrorResponse
// @Success 500 {object} presenter.ErrorResponse
// @Router /v1/customers/{customer_id} [get]
func (impl *CustomerController) FindByID(ctx *gin.Context) {
	id := ctx.Param("customer_id")
	customerID, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, presenter.ErrorResponse{
			Error:   http.StatusText(http.StatusBadRequest),
			Message: "invalid customer id",
		})
		return
	}

	res, err := impl.customerService.FindByID(ctx, customerID)
	if err != nil {
		if e, ok := err.(*exception.NotFoundException); ok {
			ctx.JSON(http.StatusNotFound, presenter.ErrorResponse{
				Error:   http.StatusText(http.StatusNotFound),
				Message: e.Error(),
			})
			return
		}

		ctx.JSON(http.StatusInternalServerError, presenter.ErrorResponse{Error: http.StatusText(http.StatusInternalServerError)})
		return
	}

	ctx.JSON(http.StatusOK, impl.parse(res))
}

// Customer godoc
// @Summary update customer
// @Schemes
// @Tags customers
// @Accept json
// @Produce json
// @Param customer_id path int true "customer_id"
// @Param customer body presenter.CustomerDataRequest true "Customer"
// @Success 200 {object} presenter.CustomerResponseData
// @Success 400 {object} presenter.ErrorResponse
// @Success 404 {object} presenter.ErrorResponse
// @Success 500 {object} presenter.ErrorResponse
// @Router /v1/customers/{customer_id} [patch]
func (impl *CustomerController) Update(ctx *gin.Context) {
	id := ctx.Param("customer_id")
	customerID, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, presenter.ErrorResponse{
			Error:   http.StatusText(http.StatusBadRequest),
			Message: "invalid customer id",
		})
		return
	}

	var req presenter.CustomerUpdateRequest
	ctx.BindJSON(&req)

	updatedAt, err := time.Parse(time.DateTime, req.UpdatedAt)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, presenter.ErrorResponse{
			Error:   http.StatusText(http.StatusBadRequest),
			Message: "invalid updated_at",
		})
		return
	}

	data := dto.CustomerUpdateData{
		ID:        customerID,
		FullName:  req.FullName,
		Email:     req.Email,
		UpdatedAt: updatedAt,
	}

	res, err := impl.customerService.Update(ctx, data)
	if err != nil {
		if e, ok := err.(*exception.ValidationException); ok {
			ctx.JSON(http.StatusBadRequest, presenter.ErrorResponse{
				Error:    http.StatusText(http.StatusBadRequest),
				Messages: e.Errors,
			})
			return
		}
		if e, ok := err.(*exception.NotFoundException); ok {
			ctx.JSON(http.StatusNotFound, presenter.ErrorResponse{
				Error:   http.StatusText(http.StatusNotFound),
				Message: e.Error(),
			})
			return
		}

		ctx.JSON(http.StatusInternalServerError, presenter.ErrorResponse{Error: http.StatusText(http.StatusInternalServerError)})
		return
	}

	ctx.JSON(http.StatusOK, impl.parse(res))
}

func (impl *CustomerController) parse(c *model.Customer) presenter.CustomerResponseData {
	return presenter.CustomerResponseData{
		ID:        c.ID,
		CreatedAt: c.CreatedAt.Format(time.DateTime),
		UpdatedAt: c.UpdatedAt.Format(time.DateTime),
		FullName:  c.FullName,
		Email:     c.Email,
	}
}
