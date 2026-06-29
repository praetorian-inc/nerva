# WinRM mock server for integration testing
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy server source
COPY server.go .

# Build the mock server
RUN go build -o winrm-mock server.go

# Final stage
FROM alpine:3.20

# Create non-root user
RUN addgroup -S app && adduser -S -G app app

# Copy the binary from builder
COPY --from=builder /app/winrm-mock /usr/local/bin/

EXPOSE 8985 8986 8080

USER app

CMD ["winrm-mock"]
