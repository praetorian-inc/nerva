# phpMyAdmin mock server for integration testing
FROM golang:1.21-alpine AS builder

WORKDIR /app

COPY server.go .

RUN go build -o phpmyadmin-mock server.go

FROM alpine:3.20

RUN addgroup -S app && adduser -S -G app app

COPY --from=builder /app/phpmyadmin-mock /usr/local/bin/

ENV PORT=8080
EXPOSE 8080

USER app

CMD ["phpmyadmin-mock"]
