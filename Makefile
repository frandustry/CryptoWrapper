GO ?= go
PREFIX ?= /usr/local

.PHONY: build test integration-test check install clean

build:
	mkdir -p bin
	$(GO) build -trimpath -o bin/cw ./cmd/cw

test:
	$(GO) test ./...

integration-test:
	CW_INTEGRATION=1 $(GO) test -count=1 ./internal/integration

check:
	test -z "$$(gofmt -l $$(find . -name '*.go' -not -path './.cache/*'))"
	$(GO) vet ./...
	$(GO) test -race ./...
	git diff --check

install:
	$(GO) install ./cmd/cw

clean:
	$(GO) clean

