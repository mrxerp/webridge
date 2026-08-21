.PHONY: build run test docker-build docker-run docker-stop clean lint fmt vet

BINARY_NAME := proxy-downloader
BUILD_DIR := ./bin
LDFLAGS := -ldflags "-s -w"

build:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/server

run: build
	$(BUILD_DIR)/$(BINARY_NAME) -config configs/config.yaml.example

test:
	go test -v -race -count=1 ./...

docker-build:
	docker build -t proxy-downloader:latest -f deploy/docker/Dockerfile .

docker-run:
	docker compose -f deploy/docker/docker-compose.yml up -d

docker-stop:
	docker compose -f deploy/docker/docker-compose.yml down

docker-logs:
	docker compose -f deploy/docker/docker-compose.yml logs -f

clean:
	rm -rf $(BUILD_DIR)
	go clean -cache

lint:
	golangci-lint run ./...

fmt:
	go fmt ./...

vet:
	go vet ./...

tidy:
	go mod tidy

help:
	@echo "Available targets:"
	@echo "  build        - Build binary to ./bin/"
	@echo "  run          - Build and run locally"
	@echo "  test         - Run tests"
	@echo "  docker-build - Build Docker image"
	@echo "  docker-run   - Run with docker-compose"
	@echo "  docker-stop  - Stop docker-compose"
	@echo "  docker-logs  - Follow docker logs"
	@echo "  clean        - Clean build artifacts"
	@echo "  lint         - Run golangci-lint"
	@echo "  fmt          - Format code"
	@echo "  vet          - Run go vet"
	@echo "  tidy         - Run go mod tidy"