# APISIX mock server for integration testing
FROM golang:1.21-alpine AS builder

WORKDIR /app

COPY server.go .

RUN go build -o apisix-mock server.go

FROM alpine:3.20

RUN addgroup -S app && adduser -S -G app app

COPY --from=builder /app/apisix-mock /usr/local/bin/

ENV PORT=9180
EXPOSE 9180

USER app

CMD ["apisix-mock"]
