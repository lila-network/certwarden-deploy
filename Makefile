# Set the default Go build flags
GOFLAGS = -ldflags='-w -s -X constants.Version=$(VERSION)'

# Build the application
build:
	go build $(GOFLAGS) -o bin/certwarden-deploy cmd/certwarden-deploy/main.go 

# Clean the build artifacts
clean:
	rm -rf bin

# Set a version for the build
VERSION := $(shell git describe --tags --always)
