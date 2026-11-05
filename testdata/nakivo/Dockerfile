FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY server.go .

RUN go build -o nakivo-mock server.go

FROM alpine:3.21

RUN addgroup -S app && adduser -S -G app app

COPY --from=builder /app/nakivo-mock /usr/local/bin/

ENV PORT=4443
EXPOSE 4443

USER app

CMD ["nakivo-mock"]
