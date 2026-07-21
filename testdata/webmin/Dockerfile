# Webmin (MiniServ) mock server for integration testing
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy server source
COPY server.go .

# Build the mock server
RUN go build -o webmin-mock server.go

# Final stage
FROM alpine:3.20

# Create non-root user
RUN addgroup -S app && adduser -S -G app app

# Copy the binary from builder
COPY --from=builder /app/webmin-mock /usr/local/bin/

# Non-privileged port by default
ENV PORT=10000
EXPOSE 10000

USER app

# Run the mock server
CMD ["webmin-mock"]
