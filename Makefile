.PHONY: build test lint clean build-docker destroy-docker dev setup fmt vet coverage

# Development setup
setup:
	@echo "🔧 Setting up development environment..."
	go mod download
	go mod tidy
	@echo "✅ Development environment ready!"

# Build binaries
build:
	@echo "🏗️ Building PhantomCore..."
	go build -o bin/controlplane ./cmd/controlplane
	go build -o bin/dataplane ./cmd/dataplane
	@echo "✅ Build completed!"

# Run tests
test:
	@echo "🧪 Running tests..."
	go test -v ./...

# Run tests with coverage
coverage:
	@echo "📊 Running tests with coverage..."
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "✅ Coverage report generated: coverage.html"

# Format code
fmt:
	@echo "🎨 Formatting code..."
	go fmt ./...

# Vet code
vet:
	@echo "🔍 Vetting code..."
	go vet ./...

# Lint code
lint:
	@echo "🔧 Linting code..."
	golangci-lint run

# Development with Docker
dev: build-docker
	@echo "🚀 Development environment started!"

build-docker: 
	@echo "🐳 Building Docker containers..."
	docker-compose up -d --build

destroy-docker: 
	@echo "🧹 Destroying Docker containers..."
	docker-compose down

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	rm -rf bin/
	rm -f coverage.out coverage.html
	@echo "✅ Cleanup completed!"

# Help target
help:
	@echo "PhantomCore Development Commands:"
	@echo "  setup        - Setup development environment"
	@echo "  build        - Build binaries"
	@echo "  test         - Run tests"
	@echo "  coverage     - Run tests with coverage report"
	@echo "  fmt          - Format code"
	@echo "  vet          - Vet code"
	@echo "  lint         - Lint code"
	@echo "  dev          - Start development environment"
	@echo "  build-docker - Build and start Docker containers"
	@echo "  destroy-docker - Stop and remove Docker containers"
	@echo "  clean        - Clean build artifacts"
	@echo "  help         - Show this help message"