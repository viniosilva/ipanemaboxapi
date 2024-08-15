package factory

import "github.com/viniosilva/ipanemaboxapi/internal/controller"

type Factory struct {
	HealthCheckController *controller.HealthCheckController
	CustomerController    *controller.CustomerController
}

func Build() Factory {
	return Factory{
		HealthCheckController: controller.NewHealthCheckController(),
		CustomerController:    controller.NewCustomerController(),
	}
}
