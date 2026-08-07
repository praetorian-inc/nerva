FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY server.go .
RUN go build -o spatialstudio-mock server.go

FROM alpine:3.20

RUN addgroup -S app && adduser -S -G app app
COPY --from=builder /app/spatialstudio-mock /usr/local/bin/

ENV PORT=4040
ENV MODE=full
EXPOSE 4040

USER app
CMD ["spatialstudio-mock"]
