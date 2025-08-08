# Set the default Go build flags
GOFLAGS = -ldflags='-w -s -X gitlab.lila.network/lila-network/certwarden-deploy/internal/constants.Version=$(VERSION)'

.PHONY: test

# Build the application
build:
	go build $(GOFLAGS) -o bin/certwarden-deploy cmd/certwarden-deploy/main.go 

# Clean the build artifacts
clean:
	rm -rf bin

# Run go tests
test:
	go test -cover ./...

coverage:
	go test -coverprofile=cover.profile ./... && go tool cover -func cover.profile

# Set a version for the build
VERSION := $(shell git describe --tags --always)
