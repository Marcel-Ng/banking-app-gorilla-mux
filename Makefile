build:
	@go build -o bin/banking-app-gorilla-mux

run: build
	@./bin/banking-app-gorilla-mux

test:
	@go test -v ./...