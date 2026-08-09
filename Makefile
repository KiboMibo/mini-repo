BINARY := apprepo

.PHONY: build test run

build:
	go build -o $(BINARY) ./cmd/apprepo

test:
	go test ./...

run:
	go run ./cmd/apprepo
