.PHONY: build test clean

build:
	mkdir -p bin
	go build -o bin/cryptool ./cmd/cryptool

test:
	go test -v ./internal/...

clean:
	rm -rf bin/