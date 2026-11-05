FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY server.go .
RUN go build -o mft-mock server.go

FROM alpine:3.20

RUN addgroup -S app && adduser -S -G app app
COPY --from=builder /app/mft-mock /usr/local/bin/

ENV PORT=7011
ENV MODE=full
EXPOSE 7011

USER app
CMD ["mft-mock"]
