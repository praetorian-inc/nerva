FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY server.go .
RUN go build -o server server.go

FROM alpine:3.21
RUN adduser -D -u 1000 appuser
USER appuser
WORKDIR /app
COPY --from=builder /app/server .
EXPOSE 8090
CMD ["./server"]
