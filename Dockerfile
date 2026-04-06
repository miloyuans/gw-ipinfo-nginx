FROM golang:1.22 AS builder

WORKDIR /src

COPY go.mod ./
COPY . .

ENV CGO_ENABLED=0
RUN go build -trimpath -ldflags="-s -w" -o /out/gw-ipinfo-nginx ./cmd/gateway

FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S app -g 10001 && \
    adduser -S -D -H -u 10001 -G app app

WORKDIR /app

COPY --from=builder /out/gw-ipinfo-nginx /app/gw-ipinfo-nginx
COPY --chown=app:app configs /app/configs

USER 10001:10001

EXPOSE 8080

ENTRYPOINT ["/app/gw-ipinfo-nginx"]
