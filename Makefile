BINARY     := gated
CMD        := ./cmd/gated
PREFIX     := /usr/local
CONF_DIR   := /etc/gated
STATE_DIR  := /var/lib/gated/verdicts

GO         := go
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT     ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')

LDFLAGS    := -s -w \
	-X main.version=$(VERSION) \
	-X main.commit=$(COMMIT) \
	-X main.buildDate=$(BUILD_DATE)
GOFLAGS    := -trimpath -ldflags="$(LDFLAGS)"

.PHONY: build test vet lint install install-config install-tools validate \
        clean build-all build-linux build-darwin build-windows check tidy

## Build

build:
	$(GO) build $(GOFLAGS) -o $(BINARY) $(CMD)

build-all: build-linux build-darwin build-windows

build-linux:
	GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BINARY)-linux-amd64 $(CMD)
	GOOS=linux GOARCH=arm64 $(GO) build $(GOFLAGS) -o $(BINARY)-linux-arm64 $(CMD)

build-darwin:
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=1 $(GO) build $(GOFLAGS) -o $(BINARY)-darwin-amd64 $(CMD)
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 $(GO) build $(GOFLAGS) -o $(BINARY)-darwin-arm64 $(CMD)

build-windows:
	@echo "Windows build compiles but watcher is stub-only (not yet implemented)."
	GOOS=windows GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BINARY)-windows-amd64.exe $(CMD)

## Test & Lint

test:
	$(GO) test ./... -v -race -count=1

vet:
	$(GO) vet ./...

lint: vet
	@command -v staticcheck >/dev/null 2>&1 && staticcheck ./... || echo "staticcheck not installed, skipping"

tidy:
	$(GO) mod tidy

## Install (system-wide, requires root for fanotify mode)

install: build
	install -Dm755 $(BINARY) $(PREFIX)/bin/$(BINARY)
	install -dm700 $(STATE_DIR)

install-config:
	install -dm755 $(CONF_DIR)/policy
	@test -f $(CONF_DIR)/config.yaml || install -Dm644 configs/config.example.yaml $(CONF_DIR)/config.yaml
	@for f in policy/*.rego policy/data.json; do \
		test -f $(CONF_DIR)/$$f || install -Dm644 $$f $(CONF_DIR)/$$f; \
	done
	@echo "Config installed to $(CONF_DIR). Edit config.yaml for your environment."

install-systemd:
	install -Dm644 init/systemd/gated.service /etc/systemd/system/gated.service
	systemctl daemon-reload
	@echo "Unit installed. Enable with: systemctl enable --now gated"

install-tools:
	./scripts/install-tools.sh

## Validate

validate: build
	./$(BINARY) -config configs/config.example.yaml -validate

check: build validate vet
	@echo "All checks passed."

## Clean

clean:
	rm -f $(BINARY) $(BINARY)-*
