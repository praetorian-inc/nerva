# JS framework mock server for integration testing
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy server source
COPY server.go .

# Build the mock server
RUN go build -o jsframework-mock server.go

# Final stage
FROM alpine:3.20

# Create non-root user
RUN addgroup -S app && adduser -S -G app app

# Copy the binary from builder
COPY --from=builder /app/jsframework-mock /usr/local/bin/

# Use non-root port by default
ENV PORT=8899
EXPOSE 8899

USER app

# Run the mock server
CMD ["jsframework-mock"]
