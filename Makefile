.PHONY: all build test vet replay serve clean

all: vet test build

build:
	go build -o bin/routewatch ./cmd/routewatch

test:
	go test ./...

vet:
	go vet ./...

replay: bin/routewatch
	./bin/routewatch generate -config config/topology.yaml -out scenario.json
	./bin/routewatch replay -config config/topology.yaml -scenario scenario.json

serve: bin/routewatch
	./bin/routewatch generate -config config/topology.yaml -out scenario.json
	./bin/routewatch serve -config config/topology.yaml -scenario scenario.json -addr :8080 -speed 60

bin/routewatch:
	@mkdir -p bin
	go build -o bin/routewatch ./cmd/routewatch

clean:
	rm -rf bin scenario.json result.json
