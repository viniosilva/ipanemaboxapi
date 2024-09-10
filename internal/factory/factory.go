package factory

import (
	"github.com/jmoiron/sqlx"
	"github.com/viniosilva/ipanemaboxapi/internal/controller"
	"github.com/viniosilva/ipanemaboxapi/internal/repository"
	"github.com/viniosilva/ipanemaboxapi/internal/service"
)

type Factory struct {
	HealthCheckController *controller.HealthCheckController
	CustomerController    *controller.CustomerController
}

func Build(db *sqlx.DB) Factory {
	customerRepo := repository.NewCustomerRepository(db)
	customerSvc := service.NewCustomerService(customerRepo)

	return Factory{
		HealthCheckController: controller.NewHealthCheckController(),
		CustomerController:    controller.NewCustomerController(customerSvc),
	}
}
