
GO := $(shell which go)
GIT_SHA1 := $(shell git rev-parse --short HEAD)
REPO := flyio/rchab:local-dev-$(GIT_SHA1)

NO_APP_NAME = 0
NO_AUTH = 0
FLY_APP_NAME = rchab-local-dev-1337

default: help

.PHONY: help build-docker build-and-push-docker run-local run-local-no-auth test test-integration test-all lint

## show this message
help:
	@awk '/^##.*$$/,/[a-zA-Z_-]+:/' $(MAKEFILE_LIST) | awk '!(NR%2){print $$0p}{p=$$0}' | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}' | sort

## build docker image and push to registry
build-and-push-docker:
	./build.sh $(shell git branch --show-current)-$(GIT_SHA1)

## build docker image
build-docker:
	docker build --platform linux/amd64 --build-arg=$(shell git rev-parse HEAD) -t $(REPO) .

## run locally
run-local:
	@echo "Running locally using sudo..."
	sudo run-parts docker-entrypoint.d/ && \
	sudo cp etc/docker/daemon.json /etc/docker/daemon.json && \
	test -f /usr/libexec/docker/cli-plugins/docker-buildx && \
	cd dockerproxy && \
	echo "Starting dockerproxy..." && \
	sudo env NO_APP_NAME=$(NO_APP_NAME) NO_AUTH=$(NO_AUTH) FLY_APP_NAME=$(FLY_APP_NAME) $(GO) run .

## run locally and do not require auth
run-local-no-auth:
	$(MAKE) run-local NO_APP_NAME=1 NO_AUTH=1

## run Go unit tests
test:
	cd dockerproxy && go test -v ./...

## run critical integration tests (Tier 2)
test-integration:
	cd tests && ./run-tests.sh tier2

## run full test suite (Tier 3)
test-all:
	cd tests && ./run-tests.sh tier3

## run linting (go vet, gofmt)
lint:
	cd dockerproxy && go vet ./...
	@if [ -n "$$(gofmt -l dockerproxy/)" ]; then \
		echo "Code is not properly formatted:"; \
		gofmt -l dockerproxy/; \
		exit 1; \
	fi
	cd dockerproxy && go mod verify
