# syntax=docker/dockerfile:1.7

# One image, both programs: the SSH channel and the SSH factory work only
# together.
#
# The build stage runs on the builder's own platform (BUILDPLATFORM) and
# cross-compiles for each target (TARGETOS, TARGETARCH): CI builds amd64 and
# arm64 on an amd64 runner, where compiling under QEMU took about two
# minutes for arm64 against twenty seconds natively. The final stage runs no
# command, so arm64 needs no emulation at all. Docker's classic builder
# (compose without the buildx plugin) sets none of the three: BUILDPLATFORM
# defaults to amd64 below, and an empty GOOS and GOARCH build for the host.
ARG BUILDPLATFORM=linux/amd64
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS builder
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
# VERSION is reported to core at registration, and in the minion's hello.
ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags "-X main.version=${VERSION}" -o /out/ssh-channel ./cmd/ssh-channel && \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags "-X main.version=${VERSION}" -o /out/ssh-factory ./cmd/ssh-factory

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app

COPY --from=builder /out/ssh-channel /app/ssh-channel
COPY --from=builder /out/ssh-factory /app/ssh-factory
# Both are configured entirely from the environment (internal/config for
# the channel, cmd/ssh-factory/main.go for the factory). No port: they only
# dial out (to core, its RabbitMQ, and SSH servers).

ENTRYPOINT ["/app/ssh-channel"]
