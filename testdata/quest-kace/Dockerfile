# Quest KACE SMA mock server for integration testing
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy server source
COPY server.go .

# Build the mock server
RUN go build -o quest-kace-mock server.go

# Final stage
FROM alpine:3.20

# Create non-root user
RUN addgroup -S app && adduser -S -G app app

# Copy the binary from builder
COPY --from=builder /app/quest-kace-mock /usr/local/bin/

# Use non-root port by default
ENV PORT=8080
EXPOSE 8080

USER app

# Run the mock server
CMD ["quest-kace-mock"]
