FROM golang:1.21-alpine AS builder

WORKDIR /app

COPY server.go .

RUN go build -o commvault-mock server.go

FROM alpine:3.20

RUN addgroup -S app && adduser -S -G app app

COPY --from=builder /app/commvault-mock /usr/local/bin/

ENV PORT=8080
EXPOSE 8080

USER app

CMD ["commvault-mock"]
