# Makefile for nerva - Service fingerprinting utility
.PHONY: all build test test-unit test-integration clean help lint fmt vet install test-coverage
.DEFAULT_GOAL := help
.DELETE_ON_ERROR:

# Variables with environment override support
GO ?= go
BINARY_NAME ?= nerva
BUILD_DIR ?= .
CMD_DIR := ./cmd/nerva

# Go build flags
GO_FLAGS ?= -v -trimpath
GO_LDFLAGS ?= -s -w

# Test flags
TEST_FLAGS ?= -v
COVERAGE_FILE ?= coverage.out

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
	golangci-lint run ./...

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

#############################################################################
# SCTP Testing Infrastructure (requires Linux)
#############################################################################

# Include SCTP-specific targets for devcontainer testing
-include Makefile.sctp
