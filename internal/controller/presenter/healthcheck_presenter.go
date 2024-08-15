package presenter

type HealthCheckStatus string

const (
	HealthCheckStatusUp   HealthCheckStatus = "up"
	HealthCheckStatusDown HealthCheckStatus = "down"
)

type HealthCheckRes struct {
	Status HealthCheckStatus `json:"status"`
}
