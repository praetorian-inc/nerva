# PCOM Docker build for plugin testing
# Builds a mock PCOM server simulating a Unitronics V130-33-T38 PLC
#
# Build:  docker build -t pcom-test .
# Run:    docker run -d --name pcom-test -p 20256:20256/tcp pcom-test
# Test:   nerva -t 127.0.0.1:20256 --verbose
# Stop:   docker stop pcom-test && docker rm pcom-test

FROM golang:1.24-alpine AS builder

WORKDIR /build

# Copy mock server source
COPY main.go .

# Build static binary
RUN go build -o pcom-mock main.go

FROM alpine:latest

# Copy binary from builder
COPY --from=builder /build/pcom-mock /usr/local/bin/pcom-mock

# PCOM port
EXPOSE 20256/tcp

# Run mock server
CMD ["/usr/local/bin/pcom-mock"]
