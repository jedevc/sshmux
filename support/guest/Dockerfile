# syntax=docker/dockerfile:1
FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/root/go/pkg/mod \
    go mod download
COPY *.go ./
RUN --mount=type=cache,target=/root/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/guest .

FROM alpine:3.21
RUN adduser -D -s /bin/sh user
COPY --from=builder /out/guest /usr/local/bin/guest
USER user
WORKDIR /home/user
ENV HOME=/home/user
ENV SHELL=/bin/sh
ENV TERM=xterm-256color
EXPOSE 2222
CMD ["/usr/local/bin/guest"]
