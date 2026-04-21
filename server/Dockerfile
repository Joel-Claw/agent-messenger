FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=1 GOOS=linux go build -ldflags="-s -w" -o agent-messenger .

FROM alpine:latest
RUN apk --no-cache add ca-certificates wget
WORKDIR /app
COPY --from=builder /app/agent-messenger .
EXPOSE 8080
VOLUME /data
ENV DB_PATH=/data/agent-messenger.db
CMD ["./agent-messenger"]