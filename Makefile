# wifi-cracker Makefile
# Build from source and install system-wide (global).

BINARY_NAME := 8cracker
BINARY_DIR  := bin
PREFIX      ?= /usr/local
SUDO       ?=

PY ?= python3

.PHONY: all build install clean test help

all: clean build ## Clean and prepare the script for install

build: ## Copy the script into $(BINARY_DIR) and make it executable
	@mkdir -p $(BINARY_DIR)
	@chmod +x $(BINARY_NAME).py
	cp $(BINARY_NAME).py $(BINARY_DIR)/$(BINARY_NAME)

install: build ## Install the script into $(PREFIX)/bin (system-wide)
	$(SUDO) install -D -m 0755 $(BINARY_DIR)/$(BINARY_NAME) $(PREFIX)/bin/$(BINARY_NAME)

clean: ## Remove build artifacts
	@rm -rf $(BINARY_DIR)

test: ## Syntax-check the script
	$(PY) -m py_compile $(BINARY_NAME).py

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'
