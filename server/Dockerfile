FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY *.go ./
RUN go build -o agent-messenger .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/agent-messenger .
EXPOSE 8080
CMD ["./agent-messenger"]