.PHONY: build test lint clean build-docker destroy-docker

build-docker: 
	docker-compose up -d --build

destroy-docker: 
	docker-compose down

build:
	go build -o bin/controlplane ./cmd/controlplane
	go build -o bin/dataplane ./cmd/dataplane

test:
	go test -v ./...

lint:
	golangci-lint run

clean:
	rm -rf bin/