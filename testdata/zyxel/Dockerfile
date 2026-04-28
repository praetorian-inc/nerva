# Zyxel ATP mock server for integration testing
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy server source
COPY server.go .

# Build the mock server
RUN go build -o zyxel-mock server.go

# Final stage
FROM alpine:latest

# Copy the binary from builder
COPY --from=builder /app/zyxel-mock /usr/local/bin/

# Expose Zyxel web management port
EXPOSE 443

# Run the mock server
CMD ["zyxel-mock"]
