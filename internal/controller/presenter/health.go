package presenter

import "github.com/vinosilva/ipanemaboxapi/internal/model"

type HealthCheckResponse struct {
	Status model.HealthCheckStatus `json:"status" example:"down"`
}
