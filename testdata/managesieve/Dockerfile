# ManageSieve mock server for integration testing
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Copy server source
COPY server.go .

# Build the mock server
RUN go build -o managesieve-mock server.go

# Final stage
FROM alpine:3.21

# Create non-root user
RUN addgroup -S app && adduser -S -G app app

# Copy the binary from builder
COPY --from=builder /app/managesieve-mock /usr/local/bin/

# ManageSieve default port (RFC 5804)
ENV PORT=4190
EXPOSE 4190

USER app

# Run the mock server
CMD ["managesieve-mock"]
