.PHONY: all
all: build
FORCE: ;

.PHONY: build

clean:
	rm -rf bin/*

dependencies:
	go mod download

build: dependencies build-api

build-api: 
	go build -o api2 api/main.go
