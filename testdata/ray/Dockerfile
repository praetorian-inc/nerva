# Ray dashboard mock server for integration testing
FROM golang:1.21-alpine AS builder

WORKDIR /app

COPY server.go .

RUN go build -o ray-mock server.go

FROM alpine:3.20

RUN addgroup -S app && adduser -S -G app app

COPY --from=builder /app/ray-mock /usr/local/bin/

ENV PORT=8265
EXPOSE 8265

USER app

CMD ["ray-mock"]
