# Vault mock server for integration testing
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy server source
COPY server.go .

# Build the mock server
RUN go build -o vault-mock server.go

# Final stage
FROM alpine:3.20

# Create non-root user
RUN addgroup -S app && adduser -S -G app app

# Copy the binary from builder
COPY --from=builder /app/vault-mock /usr/local/bin/

EXPOSE 8200 8201 8202

USER app

# Run the mock server
CMD ["vault-mock"]
