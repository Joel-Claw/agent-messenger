FROM golang:1.25-alpine AS builder

RUN apk add --no-cache gcc musl-dev

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -ldflags="-s -w" -o agent-messenger .

FROM alpine:latest
RUN apk --no-cache add ca-certificates wget
WORKDIR /app
COPY --from=builder /app/agent-messenger .
COPY --from=builder /app/deploy/env.example /app/.env.example
EXPOSE 8080
VOLUME /data
ENV DB_DRIVER=sqlite3
ENV DB_PATH=/data/agent-messenger.db
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD wget -qO- http://localhost:8080/health || exit 1
CMD ["./agent-messenger"]