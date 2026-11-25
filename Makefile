BINARY     := gated
CMD        := ./cmd/gated
PREFIX     := /usr/local
CONF_DIR   := /etc/gated
STATE_DIR  := /var/lib/gated/verdicts

GO         := go
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null | sed 's/^v//' || echo "dev")
COMMIT     ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')

LDFLAGS    := -s -w \
	-X main.version=$(VERSION) \
	-X main.commit=$(COMMIT) \
	-X main.buildDate=$(BUILD_DATE)
GOFLAGS    := -trimpath -ldflags="$(LDFLAGS)"

# Policy tooling runs the same OPA version the daemon embeds (from go.mod).
OPA_VERSION     := $(shell $(GO) list -m -f '{{.Version}}' github.com/open-policy-agent/opa 2>/dev/null)
OPA             ?= $(GO) run github.com/open-policy-agent/opa@$(OPA_VERSION)
# Below 100 only because the `default` knob values in policy/common.rego run
# only when data.json lacks the knob (covered by internal/policy tests).
POLICY_COVERAGE ?= 95

# Keep in sync with GORELEASER_VERSION in .github/workflows/release.yml and ci.yml.
GORELEASER := $(GO) run github.com/goreleaser/goreleaser/v2@v2.20.3

.PHONY: build test vet lint fmt install install-config install-tools validate \
        clean build-all build-linux build-darwin build-windows check tidy \
        install-systemd install-systemd-unprivileged \
        policy-test policy-fmt snapshot release-check fix

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

fmt:
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt needed on:"; echo "$$unformatted"; exit 1; \
	fi

# golangci-lint (pinned; config in .golangci.yml): staticcheck, gosec,
# errorlint, revive and more, plus the analyzers `go fix` applies (modernize).
# Keep the version in sync with .github/workflows/ci.yml.
lint:
	$(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0 run ./...

# Apply go fix: what the modernize linter enforces.
fix:
	$(GO) fix ./...

tidy:
	$(GO) mod tidy

## Policies

# opa fmt (check only), strict compile, unit tests (policy/*_test.rego) with
# a coverage gate.
policy-test:
	$(OPA) fmt --list --fail policy
	$(OPA) check --strict policy
	$(OPA) test policy
	$(OPA) test policy --coverage --threshold $(POLICY_COVERAGE) > /dev/null

policy-fmt:
	$(OPA) fmt --write policy

## Install (system-wide, requires root for fanotify mode)

install: build
	install -Dm755 $(BINARY) $(PREFIX)/bin/$(BINARY)
	install -dm700 $(STATE_DIR)

install-config:
	install -dm755 $(CONF_DIR)/policy
	@test -f $(CONF_DIR)/config.yaml || install -Dm644 configs/config.example.yaml $(CONF_DIR)/config.yaml
	@for f in policy/*.rego policy/data.json; do \
		case $$f in *_test.rego) continue ;; esac; \
		test -f $(CONF_DIR)/$$f || install -Dm644 $$f $(CONF_DIR)/$$f; \
	done
	@echo "Config installed to $(CONF_DIR). Edit config.yaml for your environment."

install-systemd:
	install -Dm644 init/systemd/gated.service /etc/systemd/system/gated.service
	systemctl daemon-reload
	@echo "Unit installed. Enable with: systemctl enable --now gated"

# Unprivileged mode: creates the 'gated' system user/group the unit runs
# as (init/systemd/gated-unprivileged.service assumes it exists but
# nothing else in this repo creates it).
install-systemd-unprivileged:
	getent group gated >/dev/null || groupadd --system gated
	getent passwd gated >/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin --gid gated gated
	install -Dm644 init/systemd/gated-unprivileged.service /etc/systemd/system/gated.service
	systemctl daemon-reload
	@echo "Unit installed, running as 'gated' system user. Enable with: systemctl enable --now gated"

install-tools:
	./scripts/install-tools.sh

## Validate

validate: build
	./$(BINARY) -config configs/config.example.yaml -validate

check: build validate vet fmt lint test policy-test
	@echo "All checks passed."

## Release (GoReleaser; tags and changelog come from release-please)

# Builds and packages this host's OS family into dist/, nothing published:
# darwin targets need macOS (cgo), so on Linux this builds linux + windows.
snapshot:
	@cfg=$$(mktemp); \
	if [ "$$(uname -s)" = Darwin ]; then goos='["darwin"]'; else goos='["linux","windows"]'; fi; \
	yq ".builds[0].goos = $$goos" .goreleaser.yaml > $$cfg && \
	$(GORELEASER) release --snapshot --clean --skip=publish,sbom --config $$cfg; \
	status=$$?; rm -f $$cfg; exit $$status

release-check:
	$(GORELEASER) check

## Clean

clean:
	rm -f $(BINARY) $(BINARY)-*
	rm -rf dist
