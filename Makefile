GOBIN ?= $(shell go env GOPATH)/bin
BINDIR := .e2e/bin

.PHONY: all build install test race vet lint e2e fuzz clean

all: build

build:
	@mkdir -p $(BINDIR)
	go build -o $(BINDIR)/git-cloak ./cmd/git-cloak
	go build -o $(BINDIR)/git-remote-cloak ./cmd/git-remote-cloak

install:
	go install ./cmd/git-cloak
	go install ./cmd/git-remote-cloak
	@echo "installed git-cloak and git-remote-cloak into $(GOBIN)"

test: vet
	go test -race ./...

race:
	go test -race ./...

vet:
	go vet ./...

lint:
	@command -v staticcheck >/dev/null 2>&1 && staticcheck ./... || echo "staticcheck not installed; skipping"
	@test -z "$$(gofmt -l . | grep -v '^$$')" || { echo "gofmt needed:"; gofmt -l .; exit 1; }

# Full lifecycle integration test against a local bare repo.
e2e:
	bash test/e2e.sh

# Short fuzz smoke run of the parsers.
fuzz:
	go test ./internal/crypto/   -run xxx -fuzz FuzzOpenStream      -fuzztime 10s
	go test ./internal/crypto/   -run xxx -fuzz FuzzParseDEKSet     -fuzztime 10s
	go test ./internal/crypto/   -run xxx -fuzz FuzzOpenPassphrase  -fuzztime 10s
	go test ./internal/manifest/ -run xxx -fuzz FuzzManifestDecrypt -fuzztime 10s

clean:
	rm -rf .e2e bin dist
