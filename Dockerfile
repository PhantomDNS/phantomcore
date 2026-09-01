# Combined controlplane + dataplane Dockerfile (multi-arch)
# go.mod requires go >= 1.25.0 (see docker/controlplane.Dockerfile for why)
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS builder
ARG TARGETARCH
ARG TARGETOS=linux
WORKDIR /app

RUN apk add --no-cache git

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o /bin/controlplane ./cmd/controlplane
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o /bin/dataplane ./cmd/dataplane

# Runtime
FROM alpine:3.22
WORKDIR /app

RUN apk add --no-cache ca-certificates

# Create non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Create directories
RUN mkdir -p /app/data /app/configs && \
    chown -R appuser:appgroup /app

COPY --from=builder /bin/controlplane /app/controlplane
COPY --from=builder /bin/dataplane /app/dataplane
COPY configs/ /app/configs/
COPY docker/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

USER appuser

EXPOSE 8080 1053/udp 1053/tcp 50051

ENTRYPOINT ["/app/entrypoint.sh"]
