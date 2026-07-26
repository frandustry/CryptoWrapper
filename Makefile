GO ?= go
PREFIX ?= /usr/local
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(BUILD_DATE)

.PHONY: build test integration-test check install completions demo release clean

build:
	mkdir -p bin
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/cw ./cmd/cw

test:
	$(GO) test ./...

integration-test:
	CW_INTEGRATION=1 $(GO) test -count=1 ./internal/integration

check:
	test -z "$$(gofmt -l $$(find . -name '*.go' -not -path './.cache/*'))"
	$(GO) vet ./...
	$(GO) test -race ./...
	if command -v swiftc >/dev/null 2>&1; then swiftc -typecheck examples/swift/CryptoWrapperRPC.swift; fi
	git diff --check

install:
	$(GO) install -ldflags "$(LDFLAGS)" ./cmd/cw

completions: build
	mkdir -p bin/completions
	./bin/cw completion bash > bin/completions/cw.bash
	./bin/cw completion zsh > bin/completions/_cw
	./bin/cw completion fish > bin/completions/cw.fish

demo: build
	command -v asciinema
	mkdir -p demo
	asciinema record --overwrite --output-format asciicast-v2 \
		--idle-time-limit 1.5 --window-size 120x32 \
		--title "CryptoWrapper quick start" \
		--command ./scripts/asciinema-demo.sh \
		demo/cryptowrapper.cast --return

release:
	./scripts/build-release.sh "$(VERSION)"

clean:
	$(GO) clean
