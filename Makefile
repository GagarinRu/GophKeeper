.PHONY: test build build-all

VERSION ?= 0.1.0
DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS = -X main.buildVersion=$(VERSION) -X main.buildDate=$(DATE) -X main.buildCommit=$(COMMIT)

test:
	go test ./...

build:
	go build -ldflags "$(LDFLAGS)" -o bin/gophkeeper-server ./cmd/server
	go build -ldflags "$(LDFLAGS)" -o bin/gophkeeper-client ./cmd/client

build-all:
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o bin/gophkeeper-client-windows-amd64.exe ./cmd/client
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o bin/gophkeeper-client-linux-amd64 ./cmd/client
	GOOS=darwin GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o bin/gophkeeper-client-darwin-amd64 ./cmd/client
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o bin/gophkeeper-server-windows-amd64.exe ./cmd/server
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o bin/gophkeeper-server-linux-amd64 ./cmd/server
	GOOS=darwin GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o bin/gophkeeper-server-darwin-amd64 ./cmd/server
