# --- Builder stage ---
# SPDX-License-Identifier: GPL-3.0-or-later
FROM golang:1.23-alpine AS builder
WORKDIR /app

# Install git for go modules
RUN apk add --no-cache git

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o dataplane ./cmd/dataplane

# --- Runtime stage ---
FROM alpine:latest
WORKDIR /app

# Add CA certs (needed if you ever do HTTPS requests inside container)
RUN apk add --no-cache ca-certificates

# Create non-root user & group
RUN addgroup -g 1000 appgroup && \
    adduser -D -u 1000 -G appgroup appuser

# Copy only the built binary
COPY --from=builder /app/dataplane .

# Ensure binary is executable
RUN chmod +x /app/dataplane

# Fix the ownership and permissions for /app/data during runtime (this is crucial)
RUN mkdir -p /app/data && \
    chown -R appuser:appgroup /app/data && \
    chmod -R 775 /app/data

# Drop privileges
USER appuser

CMD ["./dataplane"]
