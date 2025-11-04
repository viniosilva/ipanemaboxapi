all:
	go mod tidy
	
install-tools:
	go install github.com/vektra/mockery/v3@v3.5.5
	go install github.com/swaggo/swag/cmd/swag@latest

swag:
	swag init -g ./cmd/server/main.go

infra-up:
	docker compose up -d

infra-down:
	docker compose down

db-migrate-create:
	docker run --rm -v ./db/migrations:/migrations migrate/migrate create -ext sql -dir ./migrations -seq ${name}

db-migrate-up:
	docker run --rm --network host \
	    -v ./db/migrations:/migrations migrate/migrate \
		-path=/migrations/ \
		-database postgres://ipanemabox-api:${POSTGRES_PASSWORD}@localhost:5432/ipanemabox?sslmode=disable \
		up

dev:
	go run cmd/server/main.go

test:
	go test -cover -v ./...

.PHONY: mocks
mocks:
	rm -rf mocks
	mockery --config .mockery.yml