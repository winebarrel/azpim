.PHONY: all
all: vet test build

.PHONY: build
build:
	go build ./cmd/azpim

.PHONY: vet
vet:
	go vet ./...

.PHONY: test
test:
	go test -v -count=1 ./... $(TEST_OPTS)

.PHONY: lint
lint:
	golangci-lint run
