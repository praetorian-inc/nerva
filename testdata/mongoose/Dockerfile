# Mongoose embedded web server for fingerprinter testing
FROM alpine:3.19 AS builder

RUN apk add --no-cache gcc musl-dev curl

# Download Mongoose source (single-file library)
WORKDIR /build
ARG MONGOOSE_VERSION=7.14
RUN curl -sL "https://raw.githubusercontent.com/cesanta/mongoose/${MONGOOSE_VERSION}/mongoose.c" -o mongoose.c && \
    curl -sL "https://raw.githubusercontent.com/cesanta/mongoose/${MONGOOSE_VERSION}/mongoose.h" -o mongoose.h

COPY main.c .

# Build with directory listing enabled
RUN gcc -DMG_ENABLE_DIRLIST=1 -o mongoose_server main.c mongoose.c -lpthread

FROM alpine:3.19

COPY --from=builder /build/mongoose_server /usr/local/bin/mongoose_server

# Create test data directory with sample files
RUN mkdir -p /data && \
    echo "test file" > /data/test.txt && \
    echo "another file" > /data/readme.txt

EXPOSE 8000

HEALTHCHECK --interval=5s --timeout=3s --retries=5 \
  CMD wget -q --spider http://localhost:8000/ || exit 1

CMD ["mongoose_server"]
