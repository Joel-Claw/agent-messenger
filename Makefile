.PHONY: build test clean admin docker deploy

# Build the server
build:
	cd server && go build -ldflags="-s -w" -o agent-messenger .

# Build the admin CLI
admin:
	cd server && go build -ldflags="-s -w" -o am-admin ./cmd/am-admin

# Run server tests
test:
	cd server && go test -count=1 -timeout 120s ./...

# Run server tests (cached)
test-fast:
	cd server && go test ./...

# Clean build artifacts
clean:
	rm -f server/agent-messenger server/am-admin server/server server/agent-messenger-server server/server.test
	rm -rf server/data/*.db

# Build Docker image
docker:
	docker build -t agent-messenger:latest ./server

# Run with docker-compose (requires .env or env vars)
docker-up:
	docker-compose up -d

docker-down:
	docker-compose down

# Show server health
health:
	curl -s http://localhost:8080/health | python3 -m json.tool 2>/dev/null || curl -s http://localhost:8080/health

# Show server metrics
metrics:
	curl -s http://localhost:8080/metrics

# Install as systemd service (requires sudo)
deploy:
	sudo ./deploy/install.sh