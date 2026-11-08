# identity. GNU make and BSD make alike: no conditionals or functions specific
# to either; decisions run in the shell. Plain `make` prints the targets.

BINARY := identity
SRC := ./cmd/identity
BIN_DIR := bin

VERSION_DEFAULT != git describe --tags --always --dirty 2>/dev/null || echo dev
VERSION ?= $(VERSION_DEFAULT)
GIT_COMMIT_DEFAULT != git rev-parse --short HEAD 2>/dev/null || echo unknown
GIT_COMMIT ?= $(GIT_COMMIT_DEFAULT)
# SOURCE_DATE_EPOCH makes package builds reproducible; GNU date takes -d, BSD date -r.
BUILD_TIME_DEFAULT != f='+%Y-%m-%d_%H:%M:%S'; e="$${SOURCE_DATE_EPOCH:-}"; \
	if [ -n "$$e" ]; then date -u -d "@$$e" "$$f" 2>/dev/null || date -u -r "$$e" "$$f"; else date -u "$$f"; fi
BUILD_TIME ?= $(BUILD_TIME_DEFAULT)
VERSION_LDFLAGS = -X 'github.com/lixenwraith/identity/internal/version.Version=$(VERSION)' \
	-X 'github.com/lixenwraith/identity/internal/version.GitCommit=$(GIT_COMMIT)' \
	-X 'github.com/lixenwraith/identity/internal/version.BuildTime=$(BUILD_TIME)'
# Not LDFLAGS/GOFLAGS: packagers export those for the C linker and go itself.
GO_BUILDFLAGS ?=
GO_LDFLAGS ?=

# FreeBSD packages each Go release under its own name: go.mod's 1.27 is go127.
GO_DEFAULT != uname -s | grep -q FreeBSD && sed -n 's/^go \([0-9]*\)\.\([0-9]*\).*/go\1\2/p' go.mod 2>/dev/null | grep . || echo go
GO ?= $(GO_DEFAULT)
# The gofmt of the toolchain go.mod names, not an older one on PATH.
GOFMT = "$$($(GO) env GOROOT)/bin/gofmt"
GO_FILES = $$(find cmd internal schema -name '*.go')

.MAIN: help
.DEFAULT_GOAL := help
# Goals run in the order given, so make vet fmt-check test reports in that order.
.NOTPARALLEL:

.PHONY: help check-go build release test vet fmt-check fmt verify clean version

help:
	@echo "Usage: make <target> [VARIABLE=value ...]"
	@echo ""
	@echo "Build:"
	@echo "  build        Build $(BIN_DIR)/$(BINARY) with version metadata"
	@echo "  release      Build it static, stripped and trimmed (CGO_ENABLED=0)"
	@echo "  version      Print the version metadata a build embeds"
	@echo "  clean        Remove $(BIN_DIR)/"
	@echo "Check:"
	@echo "  test         Run the Go tests"
	@echo "  vet          go vet ./..."
	@echo "  fmt-check    gofmt -l on every Go file, with the toolchain's own gofmt"
	@echo "  fmt          gofmt -w the same files"
	@echo "  verify       vet, fmt-check, test, the static and linux/arm64 builds, a syntax check of the deploy scripts"
	@echo ""
	@echo "Variables: GO=$(GO) GO_BUILDFLAGS, GO_LDFLAGS (extra go build and linker flags)"

check-go:
	@command -v $(GO) >/dev/null 2>&1 || { \
		echo "Go toolchain '$(GO)' not found; go.mod requires go $$(sed -n 's/^go //p' go.mod)."; \
		if [ "$$(uname -s)" = FreeBSD ]; then echo "  FreeBSD: pkg install $(GO_DEFAULT)"; \
		elif [ -f /etc/arch-release ]; then echo "  Arch Linux: pacman -S go"; \
		else echo "  Elsewhere: https://go.dev/dl/ (distribution packages often lag)"; fi; \
		echo "  Or name a toolchain: make GO=/path/to/go ..."; \
		exit 1; }

build: check-go
	$(GO) build $(GO_BUILDFLAGS) -ldflags "$(VERSION_LDFLAGS) $(GO_LDFLAGS)" -o $(BIN_DIR)/$(BINARY) $(SRC)

release: check-go
	CGO_ENABLED=0 $(GO) build -trimpath $(GO_BUILDFLAGS) -ldflags "-s -w $(VERSION_LDFLAGS) $(GO_LDFLAGS)" -o $(BIN_DIR)/$(BINARY) $(SRC)

test: check-go
	$(GO) test ./...

vet: check-go
	$(GO) vet ./...

fmt-check: check-go
	@bad=$$($(GOFMT) -l $(GO_FILES)); \
	if [ -n "$$bad" ]; then echo "gofmt -l reports:"; echo "$$bad"; exit 1; fi

fmt: check-go
	$(GOFMT) -w $(GO_FILES)

# The node runs linux/amd64; arm64 keeps the build portable, and the static
# build is what the unit installs.
verify: vet fmt-check test
	CGO_ENABLED=0 $(GO) build -o /dev/null $(SRC)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -o /dev/null $(SRC)
	bash -n deploy/backup.sh
	sh -n deploy/update-identity.sh

clean:
	rm -rf $(BIN_DIR)

version:
	@echo "Version:    $(VERSION)"
	@echo "Commit:     $(GIT_COMMIT)"
	@echo "Build time: $(BUILD_TIME)"
