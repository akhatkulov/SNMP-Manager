.PHONY: build run test clean docker

# Variables
APP_NAME := snmp-manager
VERSION := $(shell git describe --tags --always 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)"

## build: Build the application
build:
	@echo "🔨 Building $(APP_NAME) $(VERSION)..."
	go build $(LDFLAGS) -o bin/$(APP_NAME) ./cmd/snmpmanager
	@echo "✅ Build complete: bin/$(APP_NAME)"

## run: Run the application
run: build
	@echo "🚀 Running $(APP_NAME)..."
	./bin/$(APP_NAME) --config configs/config.yaml

## dev: Run in development mode with console logging
dev:
	go run ./cmd/snmpmanager --config configs/config.yaml

## test: Run tests
test:
	go test -v -race ./...

## test-cover: Run tests with coverage
test-cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "📊 Coverage report: coverage.html"

## lint: Run linters
lint:
	go vet ./...
	@echo "✅ Lint passed"

## clean: Clean build artifacts
clean:
	rm -rf bin/ coverage.out coverage.html logs/
	@echo "🧹 Cleaned"

## docker-build: Build Docker image
docker-build:
	docker build -t $(APP_NAME):$(VERSION) -t $(APP_NAME):latest .

## docker-run: Run in Docker
docker-run: docker-build
	docker run -it --rm \
		-p 1620:162/udp \
		-p 8080:8080 \
		-p 9090:9090 \
		-v $(PWD)/configs:/etc/snmp-manager \
		-v $(PWD)/logs:/var/log/snmp-manager \
		$(APP_NAME):latest

## tidy: Tidy go modules
tidy:
	go mod tidy

## help: Show this help message
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^## ' Makefile | sed 's/## /  /'
