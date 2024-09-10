all:
	go install go.uber.org/mock/mockgen@latest
	go install github.com/golang-migrate/migrate/v4/cmd/migrate@latest
	go mod tidy

infra/up:
	docker compose up -d db

infra/test/up:
	docker compose up -d db-test

infra/down:
	docker compose down --remove-orphans

infra/test/down:
	docker compose down --remove-orphans -d db-test

db/migrate:
	go run db/migrate.go -host=localhost \
		-port=5432 \
		-dbName=ipanemabox \
		-username=admin \
		-password=S3CR31

db/test/migrate:
	go run db/migrate.go -host=localhost \
		-port=5433 \
		-dbName=ipanemabox_test \
		-username=admin \
		-password=password

dev:
	go run cmd/api/main.go

mocks:
	mockgen -source=internal/controller/customer_controller.go -destination=mock/customer_controller_mock.go -package=mock
	mockgen -source=internal/service/customer_service.go -destination=mock/customer_service_mock.go -package=mock

.PHONY: test
test:
	go test -cover ./internal/...

test/e2e:
	go test ./test/...