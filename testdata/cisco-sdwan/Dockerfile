# Cisco SD-WAN Manager mock server for integration testing
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy server source
COPY server.go .

# Build the mock server
RUN go build -o cisco-sdwan-mock server.go

# Final stage
FROM alpine:3.20

# Create non-root user
RUN addgroup -S app && adduser -S -G app app

# Copy the binary from builder
COPY --from=builder /app/cisco-sdwan-mock /usr/local/bin/

# Use non-root port by default
ENV PORT=8080
EXPOSE 8080

USER app

# Run the mock server
CMD ["cisco-sdwan-mock"]
