# ProConOS mock server for integration testing
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy server source
COPY server.go .

# Build the mock server
RUN go build -o proconos-mock server.go

# Final stage
FROM alpine:latest

# Copy the binary from builder
COPY --from=builder /app/proconos-mock /usr/local/bin/

# Expose ProConOS default port
EXPOSE 20547

# Run the mock server
CMD ["proconos-mock"]
