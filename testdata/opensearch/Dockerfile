# OpenSearch mock server for integration testing
FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY server.go .

RUN go build -o opensearch-mock server.go

FROM alpine:3.20

RUN addgroup -S app && adduser -S -G app app

COPY --from=builder /app/opensearch-mock /usr/local/bin/

ENV PORT=9200
EXPOSE 9200

USER app

CMD ["opensearch-mock"]
