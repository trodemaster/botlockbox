BINARY := bin/botlockbox
MODULE := github.com/trodemaster/botlockbox

.PHONY: build install test lint tidy clean

build:
	go build -o $(BINARY) ./cmd/botlockbox

install:
	go install $(MODULE)

test:
	go test -race ./...

lint:
	go vet ./...

tidy:
	go mod tidy

clean:
	rm -rf bin/
