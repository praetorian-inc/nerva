# Samsung MagicINFO mock server for integration testing
FROM golang:1.21-alpine AS builder

WORKDIR /app

COPY server.go .

RUN go build -o magicinfo-mock server.go

FROM alpine:3.20

RUN addgroup -S app && adduser -S -G app app

COPY --from=builder /app/magicinfo-mock /usr/local/bin/

ENV PORT=7001
EXPOSE 7001

USER app

CMD ["magicinfo-mock"]
