FROM golang:1.22 AS builder

WORKDIR /src
COPY go.mod ./
COPY . .
RUN go build -o /out/gw-ipinfo-nginx ./cmd/gateway

FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /out/gw-ipinfo-nginx /app/gw-ipinfo-nginx
COPY configs /app/configs
EXPOSE 8080
ENTRYPOINT ["/app/gw-ipinfo-nginx"]
