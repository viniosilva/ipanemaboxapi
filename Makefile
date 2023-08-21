include .env
export

all:
	go install github.com/golang/mock/mockgen@v1.6.0
	go install github.com/swaggo/swag/cmd/swag@latest
	go install -tags 'mysql' github.com/golang-migrate/migrate/v4/cmd/migrate@latest
	go get

infra/up:
	docker-compose up --build -d

infra/down:
	docker-compose down --remove-orphans

db/migration/up:
	migrate -database mysql://user_admin:$(MYSQL_PASSWORD)@tcp(localhost:3307)/ipanemabox -path db/migrations up

swag:
	swag init

clean-mocks:
	rm -r ./mock

PHONY: mock
mock: clean-mocks
	go generate ./...

test/unit:
	go test ./internal/... -cover

test/unit/cov:
	go test ./internal/... -coverprofile=coverage.out
	go tool cover -html=coverage.out

test/integration:
	go test ./test/... -cover

run:
	go run ./main.go