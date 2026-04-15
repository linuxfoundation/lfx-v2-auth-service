# Copyright The Linux Foundation and each contributor to LFX.
# SPDX-License-Identifier: MIT

APP_NAME := lfx-v2-auth-service
VERSION := $(shell git describe --tags --always)
BUILD_TIME := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
GIT_COMMIT := $(shell git rev-parse HEAD)

# Docker
DOCKER_REGISTRY := ghcr.io/linuxfoundation
DOCKER_IMAGE := $(DOCKER_REGISTRY)/$(APP_NAME)
DOCKER_TAG := $(VERSION)

# Helm variables
HELM_CHART_PATH=./charts/lfx-v2-auth-service
HELM_RELEASE_NAME=lfx-v2-auth-service
HELM_NAMESPACE=lfx

# Go
GO_VERSION := 1.25.0
GOOS := linux
GOARCH := amd64

# Linting
GOLANGCI_LINT_VERSION := v2.2.2
LINT_TIMEOUT := 10m
LINT_TOOL=$(shell go env GOPATH)/bin/golangci-lint
GO_FILES=$(shell find . -name '*.go' -not -path './gen/*' -not -path './vendor/*')

##@ Development

.PHONY: setup-dev
setup-dev: ## Setup development tools
	@echo "Installing development tools..."
	@echo "Installing golangci-lint $(GOLANGCI_LINT_VERSION)..."
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

.PHONY: deps
deps: ## Install dependencies
	@echo "Installing dependencies..."
	go install goa.design/goa/v3/cmd/goa@latest

.PHONY: apigen
apigen: deps ## Generate API code using Goa
	goa gen github.com/linuxfoundation/lfx-v2-auth-service/cmd/server/design

.PHONY: setup
setup: ## Setup development environment
	@echo "Setting up development environment..."
	go mod download
	go mod tidy

.PHONY: lint
lint: ## Run golangci-lint (local Go linting)
	@echo "Running golangci-lint..."
	@which golangci-lint >/dev/null 2>&1 || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION))
	@golangci-lint run ./... && echo "==> Lint OK"

# Format code
.PHONY: fmt
fmt:
	@echo "==> Formatting code..."
	@go fmt ./...
	@gofmt -s -w $(GO_FILES)

# Check license headers (basic validation - full check runs in CI)
.PHONY: license-check
license-check:
	@echo "==> Checking license headers (basic validation)..."
	@missing_files=$$(find . \( -name "*.go" -o -name "*.html" -o -name "*.txt" \) \
		-not -path "./gen/*" \
		-not -path "./vendor/*" \
		-not -path "./megalinter-reports/*" \
		-exec sh -c 'head -10 "$$1" | grep -q "Copyright The Linux Foundation and each contributor to LFX" && head -10 "$$1" | grep -q "SPDX-License-Identifier: MIT" || echo "$$1"' _ {} \;); \
	if [ -n "$$missing_files" ]; then \
		echo "Files missing required license headers:"; \
		echo "$$missing_files"; \
		echo "Required headers:"; \
		echo "  Go files:   // Copyright The Linux Foundation and each contributor to LFX."; \
		echo "             // SPDX-License-Identifier: MIT"; \
		echo "  HTML files: <!-- Copyright The Linux Foundation and each contributor to LFX. -->"; \
		echo "             <!-- SPDX-License-Identifier: MIT -->"; \
		echo "  TXT files:  # Copyright The Linux Foundation and each contributor to LFX."; \
		echo "             # SPDX-License-Identifier: MIT"; \
		echo "Note: Full license validation runs in CI"; \
		exit 1; \
	fi
	@echo "==> Basic license header check passed"

# Check formatting and linting without modifying files
check:
	@echo "==> Checking code format..."
	@if [ -n "$$(gofmt -l $(GO_FILES))" ]; then \
		echo "The following files need formatting:"; \
		gofmt -l $(GO_FILES); \
		exit 1; \
	fi
	@echo "==> Code format check passed"
	@$(MAKE) lint
	@$(MAKE) license-check

.PHONY: test
test: ## Run tests
	@echo "Running tests..."
	go test -v -race -coverprofile=coverage.out ./...

.PHONY: build
build: apigen ## Build the application for local OS
	@echo "Building application for local development..."
	go build \
		-ldflags "-X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME) -X main.gitCommit=$(GIT_COMMIT)" \
		-o bin/$(APP_NAME) ./cmd/server

.PHONY: run
run: build ## Run the application for local development
	@echo "Running application for local development..."
	./bin/$(APP_NAME)

##@ Docker

.PHONY: docker-build
docker-build: ## Build Docker image
	@echo "Building Docker image..."
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .
	docker tag $(DOCKER_IMAGE):$(DOCKER_TAG) $(DOCKER_IMAGE):latest

.PHONY: docker-run
docker-run: ## Run Docker container locally
	@echo "Running Docker container..."
	docker run \
		--name $(APP_NAME) \
		-p 8080:8080 \
		-e NATS_URL=nats://lfx-platform-nats.lfx.svc.cluster.local:4222 \
		$(DOCKER_IMAGE):$(DOCKER_TAG)

##@ Helm/Kubernetes
# Install Helm chart
.PHONY: helm-install
helm-install:
	@echo "==> Installing Helm chart..."
	helm upgrade --install $(HELM_RELEASE_NAME) $(HELM_CHART_PATH) --namespace $(HELM_NAMESPACE)
	@echo "==> Helm chart installed: $(HELM_RELEASE_NAME)"

# Print templates for Helm chart
.PHONY: helm-templates
helm-templates:
	@echo "==> Printing templates for Helm chart..."
	helm template $(HELM_RELEASE_NAME) $(HELM_CHART_PATH) --namespace $(HELM_NAMESPACE)
	@echo "==> Templates printed for Helm chart: $(HELM_RELEASE_NAME)"

# Uninstall Helm chart
.PHONY: helm-uninstall
helm-uninstall:
	@echo "==> Uninstalling Helm chart..."
	helm uninstall $(HELM_RELEASE_NAME) --namespace $(HELM_NAMESPACE)
	@echo "==> Helm chart uninstalled: $(HELM_RELEASE_NAME)"
