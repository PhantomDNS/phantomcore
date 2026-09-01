# docker/controlplane.Dockerfile
# go.mod requires go >= 1.25.0 (golang.org/x/text v0.39.0, pulled in to close a
# reachable govulncheck finding, itself requires 1.25). Builder image bumped
# to match; this image has no GOTOOLCHAIN auto-fetch (GOTOOLCHAIN=local), so
# the builder's Go must satisfy go.mod's floor directly.
FROM golang:1.25-alpine AS builder
WORKDIR /app

# Install build dependencies including protobuf compiler
RUN apk add --no-cache git protobuf-dev protoc

COPY go.mod go.sum ./
RUN go mod download

# Install protobuf Go plugins, pinned to explicit versions (not @latest) so a
# future plugin release with a higher Go floor can't break this build again.
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11
RUN go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.1

COPY . .

# Ensure proto files are up to date (regenerate if needed)
RUN if [ -f proto/health.proto ]; then \
    protoc --go_out=. --go-grpc_out=. proto/health.proto; \
    fi

RUN go build -o controlplane ./cmd/controlplane

# Final runtime image
FROM alpine:3.22
WORKDIR /app
COPY --from=builder /app/controlplane .

# Run as non-root (we’ll map port 53 later)
USER 1000:1000

CMD ["./controlplane"]
