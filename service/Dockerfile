# Privasys Drive — TDX-attested per-tenant file storage.
#
# Reproducible OCI image; pin its `@sha256:...` digest in the
# Enclave OS Virtual workload manifest and verify it via the per-container
# OID extensions in the RA-TLS certificate.

FROM golang:1.25-bookworm AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

ARG VERSION=dev

RUN CGO_ENABLED=0 go build \
        -trimpath \
        -ldflags="-s -w -X main.version=${VERSION}" \
        -o /drive \
        ./cmd/drive

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /drive /usr/local/bin/drive

EXPOSE 8443

# No --addr: the platform injects $PORT (the serve default binds 0.0.0.0:$PORT).
ENTRYPOINT ["drive"]
CMD ["serve"]
