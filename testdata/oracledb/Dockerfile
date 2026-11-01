FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY server.go .
RUN go build -o oracledb-mock server.go

FROM alpine:3.20

RUN addgroup -S app && adduser -S -G app app
COPY --from=builder /app/oracledb-mock /usr/local/bin/

ENV PORT=1521
ENV MODE=tns-only
EXPOSE 1521

USER app
CMD ["oracledb-mock"]
