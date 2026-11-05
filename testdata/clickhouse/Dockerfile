# ClickHouse mock server for integration testing
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Copy server source
COPY server.go .

# Build the mock server
RUN go build -o clickhouse-mock server.go

# Final stage
FROM alpine:3.21

# Create non-root user
RUN addgroup -S app && adduser -S -G app app

# Copy the binary from builder
COPY --from=builder /app/clickhouse-mock /usr/local/bin/

# Native protocol and HTTP interface ports (non-privileged)
ENV NATIVE_PORT=9000
ENV HTTP_PORT=8123
EXPOSE 9000 8123

USER app

# Run the mock server
CMD ["clickhouse-mock"]
