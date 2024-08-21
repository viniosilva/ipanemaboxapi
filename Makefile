all:
	go install go.uber.org/mock/mockgen@latest
	go mod tidy

infra/up:
	docker compose up -d

dev:
	go run cmd/api/main.go

mocks:
	mockgen -source=internal/controller/customer_controller.go -destination=mock/customer_controller_mock.go -package=mock

.PHONY: test
test:
	go test -cover ./internal/...

test/e2e:
	go test ./test/...