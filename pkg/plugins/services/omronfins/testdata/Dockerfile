# OMRON FINS Docker build for plugin testing
# Builds a mock FINS server simulating an Omron PLC
#
# Build:  docker build -t fins-test .
# Run:    docker run -d --name fins-cj2m -p 9600:9600/udp -p 9600:9600/tcp fins-test
# Test:   nerva -t 127.0.0.1:9600 --verbose
# Multi-version test:
#   docker run -d --name fins-cj2m -p 9600:9600/udp -p 9600:9600/tcp fins-test -model "CJ2M-CPU31" -version "V2.1"
#   docker run -d --name fins-cs1g -p 9601:9600/udp -p 9601:9600/tcp fins-test -model "CS1G-CPU45H" -version "V3.0"
#   docker run -d --name fins-nx1p -p 9602:9600/udp -p 9602:9600/tcp fins-test -model "NX1P2-9024DT" -version "V1.49"
# Stop:   docker stop fins-cj2m fins-cs1g fins-nx1p && docker rm fins-cj2m fins-cs1g fins-nx1p

FROM golang:1.24-alpine AS builder
WORKDIR /build
COPY main.go .
RUN go build -o fins-mock main.go

FROM alpine:latest
COPY --from=builder /build/fins-mock /usr/local/bin/fins-mock
EXPOSE 9600/udp
EXPOSE 9600/tcp
ENTRYPOINT ["/usr/local/bin/fins-mock"]
