package factory

import (
	"github.com/viniosilva/ipanemaboxapi/internal/controller"
	"github.com/viniosilva/ipanemaboxapi/internal/service"
)

type Factory struct {
	HealthCheckController *controller.HealthCheckController
	CustomerController    *controller.CustomerController
}

func Build() Factory {
	customerSvc := service.NewCustomerService()

	return Factory{
		HealthCheckController: controller.NewHealthCheckController(),
		CustomerController:    controller.NewCustomerController(customerSvc),
	}
}
