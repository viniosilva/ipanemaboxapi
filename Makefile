all:
	go mod tidy

dev:
	go run cmd/api/main.go

.PHONY: test
test:
	go test -cover ./internal/...

test/e2e:
	go test ./test/...