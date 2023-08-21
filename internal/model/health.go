package model

type HealthCheckStatus string

const (
	HealthCheckStatusUp   HealthCheckStatus = "up"
	HealthCheckStatusDown HealthCheckStatus = "down"
)
