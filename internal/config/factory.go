package config

import (
	"github.com/jmoiron/sqlx"
	"github.com/vinosilva/ipanemaboxapi/internal/controller"
	"github.com/vinosilva/ipanemaboxapi/internal/infra"
	"github.com/vinosilva/ipanemaboxapi/internal/repository"
	"github.com/vinosilva/ipanemaboxapi/internal/service"
)

type ApiDependencies struct {
	HealthController   *controller.HealthController
	CustomerController *controller.CustomerController
}

func FactoryBuild(db *sqlx.DB) ApiDependencies {
	healthRepository := repository.NewHealth(db)
	customerRepository := repository.NewCustomer(db)

	healthService := service.NewHealth(healthRepository, infra.Zap)
	customerService := service.NewCustomer(customerRepository, infra.Zap)

	return ApiDependencies{
		HealthController:   controller.NewHealth(healthService),
		CustomerController: controller.NewCustomer(customerService),
	}
}
