# Builder stage
FROM golang:1.21-alpine AS builder

WORKDIR /build
COPY server.go .
RUN go build -o ipmi-mock server.go

# Final stage
FROM alpine:3.20

RUN addgroup -S app && adduser -S -G app app

COPY --from=builder /build/ipmi-mock /usr/local/bin/ipmi-mock

EXPOSE 10623/udp
EXPOSE 10624/udp
EXPOSE 10625/udp

USER app

CMD ["/usr/local/bin/ipmi-mock"]
