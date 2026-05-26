# Makefile for nerva - Service fingerprinting utility
.PHONY: all build test test-unit test-integration clean help lint fmt vet install test-coverage \
        release release-checksums
.DEFAULT_GOAL := help
.DELETE_ON_ERROR:

# Variables with environment override support
GO ?= go
BINARY_NAME ?= nerva
BUILD_DIR ?= .
DIST_DIR := dist
CMD_DIR := ./cmd/nerva

# Version info (override with: make build VERSION=1.0.0)
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

# Go build flags
GO_FLAGS ?= -v -trimpath
GO_LDFLAGS ?= -s -w

# Test flags
TEST_FLAGS ?= -v
COVERAGE_FILE ?= coverage.out

GOLANGCI_LINT_VERSION ?= v2.12.2

# Auto-discover Go source files
GO_SOURCES := $(shell find . -type f -name '*.go' -not -path './vendor/*')

#############################################################################
# Entry Points
#############################################################################

help: ## Display available targets
	@echo "Nerva - Service Fingerprinting Utility"
	@echo ""
	@echo "Usage: make <target>"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_/-]+:.*?## .*$$' Makefile | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-20s %s\n", $$1, $$2}'

all: build ## Build binary (default)

#############################################################################
# Build Targets
#############################################################################

build: $(BUILD_DIR)/$(BINARY_NAME) ## Build nerva binary

$(BUILD_DIR)/$(BINARY_NAME): $(GO_SOURCES)
	$(GO) build $(GO_FLAGS) -ldflags "$(GO_LDFLAGS)" -o $@ $(CMD_DIR)

install: build ## Install nerva to $GOPATH/bin
	$(GO) install $(CMD_DIR)

#############################################################################
# Test Targets
#############################################################################

test: test-unit ## Run all tests (unit only by default)

test-unit: ## Run unit tests
	$(GO) test $(TEST_FLAGS) ./...

test-integration: ## Run integration tests (requires Linux for SCTP)
	$(GO) test $(TEST_FLAGS) -tags=linux,integration ./...

test-coverage: ## Run tests with coverage report
	$(GO) test $(TEST_FLAGS) -coverprofile=$(COVERAGE_FILE) ./...
	$(GO) tool cover -html=$(COVERAGE_FILE)

#############################################################################
# Quality Targets
#############################################################################

lint: ## Run linters
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	elif go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) 2>/dev/null; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not available, running go vet..."; \
		go vet ./...; \
	fi

fmt: ## Format Go code
	$(GO) fmt ./...

vet: ## Run go vet
	$(GO) vet ./...

#############################################################################
# Clean Targets
#############################################################################

clean: ## Remove build artifacts
	rm -f $(BINARY_NAME)
	rm -f *.test
	rm -f $(COVERAGE_FILE)
	rm -rf $(DIST_DIR)

#############################################################################
# Release Targets (CI/CD)
#############################################################################

release: ## Build release tarballs for all platforms (outputs to dist/)
	@mkdir -p $(DIST_DIR)/staging
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -ldflags "$(GO_LDFLAGS)" -o $(DIST_DIR)/staging/$(BINARY_NAME) $(CMD_DIR)
	tar -czf $(DIST_DIR)/$(BINARY_NAME)-linux-amd64.tar.gz -C $(DIST_DIR)/staging $(BINARY_NAME)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -ldflags "$(GO_LDFLAGS)" -o $(DIST_DIR)/staging/$(BINARY_NAME) $(CMD_DIR)
	tar -czf $(DIST_DIR)/$(BINARY_NAME)-linux-arm64.tar.gz -C $(DIST_DIR)/staging $(BINARY_NAME)
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GO) build -ldflags "$(GO_LDFLAGS)" -o $(DIST_DIR)/staging/$(BINARY_NAME) $(CMD_DIR)
	tar -czf $(DIST_DIR)/$(BINARY_NAME)-darwin-amd64.tar.gz -C $(DIST_DIR)/staging $(BINARY_NAME)
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GO) build -ldflags "$(GO_LDFLAGS)" -o $(DIST_DIR)/staging/$(BINARY_NAME) $(CMD_DIR)
	tar -czf $(DIST_DIR)/$(BINARY_NAME)-darwin-arm64.tar.gz -C $(DIST_DIR)/staging $(BINARY_NAME)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -ldflags "$(GO_LDFLAGS)" -o $(DIST_DIR)/staging/$(BINARY_NAME).exe $(CMD_DIR)
	cd $(DIST_DIR)/staging && zip ../$(BINARY_NAME)-windows-amd64.zip $(BINARY_NAME).exe
	rm -rf $(DIST_DIR)/staging

release-checksums: release ## Generate checksums for release archives
	cd $(DIST_DIR) && sha256sum *.tar.gz *.zip > checksums.txt

#############################################################################
# SCTP Testing Infrastructure (requires Linux)
#############################################################################

# Include SCTP-specific targets for devcontainer testing
-include Makefile.sctp
