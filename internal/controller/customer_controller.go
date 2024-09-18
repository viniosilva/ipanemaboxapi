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
	Create(ctx context.Context, customer dto.CustomerDataDto) (*model.Customer, error)
	Find(ctx context.Context, id int64) (*model.Customer, error)
	List(ctx context.Context, page, limit int) (*dto.CustomersList, error)
	Update(ctx context.Context, id int64, customer dto.CustomerDataDto) (*model.Customer, error)
	Delete(ctx context.Context, id int64) error
}

func NewCustomerController(customerSvc CustomerService) *CustomerController {
	return &CustomerController{
		customerSvc: customerSvc,
	}
}

// CreateCustomer godoc
// @Summary      Create a new customer
// @Description  Creates a new customer and returns its details
// @Tags         customers
// @Accept       json
// @Produce      json
// @Param        customer  body      presenter.CustomerReq  true  "Customer information"
// @Success      201       {object}  presenter.CustomerRes
// @Failure      400       {object}  presenter.ErrorRes
// @Failure      500       {object}  presenter.ErrorRes
// @Router       /api/v1/customers [post]
func (c *CustomerController) Create(ctx *gin.Context) {
	var payload presenter.CustomerReq
	if err := ctx.BindJSON(&payload); err != nil {
		ctx.JSON(http.StatusBadRequest, presenter.ErrorRes{Message: err.Error()})
		return
	}

	res, err := c.customerSvc.Create(ctx, dto.CustomerDataDto{
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

// FindCustomer godoc
// @Summary      Find a customer by ID
// @Description  Retrieves a customer by their ID
// @Tags         customers
// @Accept       json
// @Produce      json
// @Param        id   path      int64  true  "Customer ID"
// @Success      200  {object}  presenter.CustomerRes
// @Failure      400  {object}  presenter.ErrorRes  "Invalid ID"
// @Failure      404  {object}  presenter.ErrorRes  "Customer not found"
// @Failure      500  {object}  presenter.ErrorRes
// @Router       /api/v1/customers/{id} [get]
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

// ListCustomers godoc
// @Summary      List customers
// @Description  Retrieves a list of customers
// @Tags         customers
// @Accept       json
// @Produce      json
// @Param        page   query     int     false  "Page number"     default(1)
// @Param        limit  query     int     false  "Items per page"  default(10)
// @Success      200    {object}  presenter.CustomersListRes
// @Failure      400    {object}  presenter.ErrorRes  "Invalid pagination parameters"
// @Failure      500    {object}  presenter.ErrorRes
// @Router       /api/v1/customers [get]
func (c *CustomerController) List(ctx *gin.Context) {
	page, err := strconv.Atoi(ctx.DefaultQuery("page", "1"))
	if err != nil || page < 1 {
		ctx.JSON(http.StatusBadRequest, presenter.ErrorRes{Message: "invalid page"})
		return
	}

	limit, err := strconv.Atoi(ctx.DefaultQuery("limit", "10"))
	if err != nil || limit < 1 {
		ctx.JSON(http.StatusBadRequest, presenter.ErrorRes{Message: "invalid limit"})
		return
	}

	res, err := c.customerSvc.List(ctx, page, limit)
	if err != nil {
		slog.ErrorContext(ctx, err.Error())
		ctx.JSON(http.StatusInternalServerError, presenter.ErrorRes{Message: presenter.INTERNAL_SERVER_ERROR_MSG})
		return
	}

	customers := make([]presenter.CustomerRes, len(res.Data))
	for i, d := range res.Data {
		customers[i] = presenter.CustomerRes{
			ID:   d.ID,
			Name: d.Name,
		}
	}

	ctx.JSON(http.StatusOK, presenter.CustomersListRes{
		Metadata: presenter.MetadataPage{
			TotalCount:  res.Meta.TotalCount,
			TotalPages:  res.Meta.TotalPages,
			CurrentPage: res.Meta.CurrentPage,
			PageSize:    res.Meta.PageSize,
		},
		Data: customers,
	})
}

// UpdateCustomer godoc
// @Summary      Update a customer by ID
// @Description  Updates an existing customer's details by their ID
// @Tags         customers
// @Accept       json
// @Produce      json
// @Param        id        path      int64  true  "Customer ID"
// @Param        customer  body      presenter.CustomerReq  true  "Customer information"
// @Success      200       {object}  presenter.CustomerRes
// @Failure      400       {object}  presenter.ErrorRes  "Invalid ID or bad request"
// @Failure      404       {object}  presenter.ErrorRes  "Customer not found"
// @Failure      500       {object}  presenter.ErrorRes  "Internal server error"
// @Router       /api/v1/customers/{id} [put]
func (c *CustomerController) Update(ctx *gin.Context) {
	idParam := ctx.Param("id")
	id, err := strconv.ParseInt(idParam, 10, 64)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, presenter.ErrorRes{Message: "invalid ID"})
		return
	}

	var payload presenter.CustomerReq
	if err := ctx.BindJSON(&payload); err != nil {
		ctx.JSON(http.StatusBadRequest, presenter.ErrorRes{Message: err.Error()})
		return
	}

	res, err := c.customerSvc.Update(ctx, id, dto.CustomerDataDto{
		Name: payload.Name,
	})
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

// DeleteCustomer godoc
// @Summary      Delete a customer
// @Description  Deletes a customer by their ID
// @Tags         customers
// @Accept       json
// @Produce      json
// @Param        id   path      int64  true  "Customer ID"
// @Success      204  "No Content"
// @Failure      400  {object}  presenter.ErrorRes  "Invalid ID"
// @Failure      500  {object}  presenter.ErrorRes  "Internal Server Error"
// @Router       /api/v1/customers/{id} [delete]
func (c *CustomerController) Delete(ctx *gin.Context) {
	idParam := ctx.Param("id")
	id, err := strconv.ParseInt(idParam, 10, 64)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, presenter.ErrorRes{Message: "invalid ID"})
		return
	}

	err = c.customerSvc.Delete(ctx, id)
	if err != nil {
		slog.ErrorContext(ctx, err.Error())
		ctx.JSON(http.StatusInternalServerError, presenter.ErrorRes{Message: presenter.INTERNAL_SERVER_ERROR_MSG})
		return
	}

	ctx.Status(http.StatusNoContent)
}
