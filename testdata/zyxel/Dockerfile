# Zyxel ATP mock server for integration testing
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy server source
COPY server.go .

# Build the mock server
RUN go build -o zyxel-mock server.go

# Final stage
FROM alpine:3.20

# Create non-root user
RUN addgroup -S app && adduser -S -G app app

# Copy the binary from builder
COPY --from=builder /app/zyxel-mock /usr/local/bin/

# Use non-root port by default
ENV PORT=8443
EXPOSE 8443

USER app

# Run the mock server
CMD ["zyxel-mock"]
