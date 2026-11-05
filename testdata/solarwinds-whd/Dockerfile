FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY server.go .

RUN go build -o solarwinds-whd-mock server.go

FROM alpine:3.21

RUN addgroup -S app && adduser -S -G app app

COPY --from=builder /app/solarwinds-whd-mock /usr/local/bin/

ENV PORT=8081
EXPOSE 8081

USER app

CMD ["solarwinds-whd-mock"]
