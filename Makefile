# 8cracker Makefile
# Builds the Go TUI (the maintained tool) and installs it system-wide.

BINARY_NAME := 8cracker
BINARY_DIR  := bin
PREFIX      ?= /usr/local
SUDO       ?=
GO         ?= go
PY         ?= python3

.PHONY: all build go-build py-build install clean test fmt lint help

all: clean go-build ## Clean and build the 8cracker TUI binary

go-build: ## Build the Go TUI into $(BINARY_DIR)/$(BINARY_NAME)
	@mkdir -p $(BINARY_DIR)
	$(GO) build -o $(BINARY_DIR)/$(BINARY_NAME) ./cmd/8cracker

py-build: ## (legacy) Copy the Python CLI from legacy/ into $(BINARY_DIR)
	@mkdir -p $(BINARY_DIR)
	@chmod +x legacy/$(BINARY_NAME).py
	cp legacy/$(BINARY_NAME).py $(BINARY_DIR)/$(BINARY_NAME)

install: go-build ## Install the TUI into $(PREFIX)/bin (system-wide)
	$(SUDO) install -D -m 0755 $(BINARY_DIR)/$(BINARY_NAME) $(PREFIX)/bin/$(BINARY_NAME)

fmt: ## Format all Go code (gofmt)
	$(GO) fmt ./...

lint: ## Vet and report unformatted files
	$(GO) vet ./...
	@test -z "$$(gofmt -l cmd internal)" || (echo "unformatted files:"; gofmt -l cmd internal; exit 1)

clean: ## Remove build artifacts
	@rm -rf $(BINARY_DIR)
	$(GO) clean

test: ## Run Go tests
	$(GO) test ./...

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'
