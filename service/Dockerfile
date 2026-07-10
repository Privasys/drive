# Privasys Drive — TDX-attested per-tenant file storage.
#
# Reproducible OCI image; pin its `@sha256:...` digest when deploying.
# Built on the Privasys RA-TLS Go fork (-tags ratls) so the service can
# open mutual RA-TLS connections to the vault constellation for
# per-tenant MEKs. The fork is fetched from its public release and the
# two modules behind the go.mod `replace` directives (ra-tls-clients,
# enclave-vaults-client) are cloned + pinned, so the image builds from
# this repo alone (build context = service/). Bump the ARGs when the
# siblings move.
ARG GO_RATLS_VERSION=privasys-v0.5.1-go1.26.5
ARG RA_TLS_CLIENTS_REF=64438d2593f26e4250bbb75e25240a5422876136
ARG ENCLAVE_VAULTS_CLIENT_REF=7cfea6e33ff809d0a13d0303726b79329ea1ae60

FROM alpine:3.21 AS toolchain
ARG GO_RATLS_VERSION
RUN apk add --no-cache curl
RUN curl -fsSL \
    "https://github.com/Privasys/go/releases/download/${GO_RATLS_VERSION}/go-ratls-${GO_RATLS_VERSION}-linux-amd64.tar.gz" \
    -o /tmp/go-ratls.tar.gz && \
    mkdir /go-ratls && \
    tar xzf /tmp/go-ratls.tar.gz -C /go-ratls --strip-components=1 && \
    rm /tmp/go-ratls.tar.gz

FROM alpine:3.21 AS builder
ARG RA_TLS_CLIENTS_REF
ARG ENCLAVE_VAULTS_CLIENT_REF
RUN apk add --no-cache git musl-dev ca-certificates
COPY --from=toolchain /go-ratls /go-ratls
ENV GOROOT=/go-ratls
ENV PATH="/go-ratls/bin:$PATH"
ENV GOPROXY=https://proxy.golang.org,direct

# The replace-directive targets, cloned + pinned.
RUN git clone https://github.com/Privasys/ra-tls-clients /siblings/ra-tls-clients && \
    git -C /siblings/ra-tls-clients checkout "${RA_TLS_CLIENTS_REF}"
RUN git clone https://github.com/Privasys/enclave-vaults-client /siblings/enclave-vaults-client && \
    git -C /siblings/enclave-vaults-client checkout "${ENCLAVE_VAULTS_CLIENT_REF}"

WORKDIR /src
# Repoint the local replace paths at the cloned siblings. Run once to
# download dependencies, then again after COPY . . (which restores the
# original go.mod).
COPY go.mod go.sum ./
RUN sed -i \
      -e 's|\.\./\.\./platform/ra-tls-clients/go|/siblings/ra-tls-clients/go|' \
      -e 's|\.\./\.\./platform/enclave-vaults-client/go|/siblings/enclave-vaults-client/go|' \
      go.mod && \
    go mod download

COPY . .

ARG VERSION=dev

RUN sed -i \
      -e 's|\.\./\.\./platform/ra-tls-clients/go|/siblings/ra-tls-clients/go|' \
      -e 's|\.\./\.\./platform/enclave-vaults-client/go|/siblings/enclave-vaults-client/go|' \
      go.mod && \
    CGO_ENABLED=0 go build -tags ratls \
        -trimpath \
        -ldflags="-s -w -X main.version=${VERSION}" \
        -o /drive \
        ./cmd/drive

# PostgreSQL rides in the image with its data directory on the sealed
# /data volume (the chat-service pattern): the index is encrypted at
# rest under the owner's key and Postgres listens on loopback only.
FROM postgres:16-bookworm

# The postgres base ships no CA bundle; the service's outbound HTTPS
# (OIDC discovery/JWKS, vault attestation) needs a trust store.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /drive /usr/local/bin/drive
# The app manifest: also baked into the org.privasys.manifest OCI label
# by CI (the platform reads capabilities from the label; the file serves
# GET /privasys.json for runtime introspection).
COPY privasys.json /privasys.json
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# No fixed port: the platform injects $PORT (host networking makes
# EXPOSE a no-op; the serve default binds 0.0.0.0:$PORT).
ENTRYPOINT ["/entrypoint.sh"]
