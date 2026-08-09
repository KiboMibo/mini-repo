BINARY := apprepo

.PHONY: build test run dist clean

build:
	go build -o $(BINARY) ./cmd/apprepo

test:
	go test ./...

run:
	go run ./cmd/apprepo

# Релизные сборки под пять платформ + SHA256SUMS в dist/ (см. scripts/dist.sh).
# VERSION и COMMIT переопределяются: make dist VERSION=v1.0.0
dist:
	bash scripts/dist.sh

clean:
	rm -rf dist $(BINARY)
