# Argo CD mock server for integration testing
FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY server.go .

RUN go build -o argocd-mock server.go

FROM alpine:3.21

RUN addgroup -S app && adduser -S -G app app

COPY --from=builder /app/argocd-mock /usr/local/bin/

ENV PORT=8080
EXPOSE 8080

USER app

CMD ["argocd-mock"]
