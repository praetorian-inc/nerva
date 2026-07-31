FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY server.go .

RUN go build -o papercut-mock server.go

FROM alpine:3.21

RUN addgroup -S app && adduser -S -G app app

COPY --from=builder /app/papercut-mock /usr/local/bin/

ENV PORT=9191
EXPOSE 9191

USER app

CMD ["papercut-mock"]
