# syntax=docker/dockerfile:1.7

FROM node:24.13.1-bookworm-slim AS frontend
WORKDIR /src
COPY frontend/package.json frontend/package-lock.json ./frontend/
RUN --mount=type=cache,target=/root/.npm npm --prefix frontend ci
COPY frontend ./frontend
RUN mkdir -p internal/frontend/dist && npm --prefix frontend run build

FROM golang:1.26.5-bookworm AS backend
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
COPY --from=frontend /src/internal/frontend/dist ./internal/frontend/dist
ARG TARGETOS=linux
ARG TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags='-s -w' -o /out/securl ./cmd/securl

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=backend --chown=nonroot:nonroot /out/securl /securl
USER nonroot:nonroot
EXPOSE 8080
ENV SECURL_HTTP_ADDR=:8080
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/securl", "healthcheck"]
ENTRYPOINT ["/securl"]
