package service

import (
	"context"
)

type HealthLogger interface {
	Error(args ...interface{})
}

type HealthService struct {
	healthRepository HealthRepository
	logger           HealthLogger
}

func NewHealth(healthRepository HealthRepository, logger HealthLogger) *HealthService {
	return &HealthService{
		healthRepository: healthRepository,
		logger:           logger,
	}
}

func (impl *HealthService) Check(ctx context.Context) error {
	err := impl.healthRepository.Ping(ctx)
	if err != nil {
		impl.logger.Error(err.Error())
	}

	return err
}
