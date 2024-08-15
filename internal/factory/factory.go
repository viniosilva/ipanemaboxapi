package factory

import "github.com/viniosilva/ipanemaboxapi/internal/controller"

type Factory struct {
	HealthCheckController *controller.HealthCheckController
}

func Build() Factory {
	return Factory{
		HealthCheckController: controller.NewHealthCheckController(),
	}
}
