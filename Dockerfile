# syntax=docker/dockerfile:1.7

# One image, both programs: the SSH channel and the SSH factory work only
# together. No GOARCH: the build stage runs as the target platform (QEMU in
# CI), so the binaries always match the image's architecture.
FROM golang:1.25-alpine AS builder
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
# VERSION is reported to core at registration, and in the minion's hello.
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -ldflags "-X main.version=${VERSION}" -o /out/ssh-channel ./cmd/ssh-channel && \
    CGO_ENABLED=0 go build -ldflags "-X main.version=${VERSION}" -o /out/ssh-factory ./cmd/ssh-factory

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app

COPY --from=builder /out/ssh-channel /app/ssh-channel
COPY --from=builder /out/ssh-factory /app/ssh-factory
# Both are configured entirely from the environment (internal/config for
# the channel, cmd/ssh-factory/main.go for the factory). No port: they only
# dial out (to core, its RabbitMQ, and SSH servers).

ENTRYPOINT ["/app/ssh-channel"]
