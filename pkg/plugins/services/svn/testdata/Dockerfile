FROM golang:1.24-alpine

WORKDIR /app
COPY main.go .
RUN CGO_ENABLED=0 go build -o /mockserver main.go

EXPOSE 3690
CMD ["/mockserver"]
