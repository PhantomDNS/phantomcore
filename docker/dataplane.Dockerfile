# docker/dataplane.Dockerfile
FROM golang:1.23-alpine AS builder
WORKDIR /app

# Install git for go get
RUN apk add --no-cache git

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o dataplane ./cmd/dataplane

# Final runtime image
FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/dataplane .

# Run as non-root (we’ll map port 53 later)
USER 1000:1000

CMD ["./dataplane"]
