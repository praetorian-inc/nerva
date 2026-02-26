FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY main.go .
RUN go build -o mock-git-daemon main.go

FROM alpine:latest
COPY --from=builder /app/mock-git-daemon /usr/local/bin/
EXPOSE 9418/tcp
ENTRYPOINT ["mock-git-daemon"]
