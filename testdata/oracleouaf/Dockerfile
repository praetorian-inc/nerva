FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY server.go .
RUN go build -o ouaf-mock server.go

FROM alpine:3.20

RUN addgroup -S app && adduser -S -G app app
COPY --from=builder /app/ouaf-mock /usr/local/bin/

ENV PORT=6501
ENV MODE=ouaf
EXPOSE 6501

USER app
CMD ["ouaf-mock"]
