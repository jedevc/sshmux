# syntax=docker/dockerfile:1
FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/root/go/pkg/mod \
    go mod download
COPY . ./
RUN --mount=type=cache,target=/root/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/sshmux ./cmd/sshmux

FROM alpine:3.21
RUN apk add --no-cache libcap && adduser -D -s /bin/sh user
COPY --from=builder /out/sshmux /usr/local/bin/sshmux
RUN setcap cap_net_bind_service=+ep /usr/local/bin/sshmux
USER user
WORKDIR /home/user
ENV HOME=/home/user
ENV SHELL=/bin/sh
ENV TERM=xterm-256color
EXPOSE 22
ENTRYPOINT ["/usr/local/bin/sshmux"]
