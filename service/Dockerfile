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
ARG RA_TLS_CLIENTS_REF=67a20d31197cebe8fa621925f4f2affa3e3822f4
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
# pgvector backs the semantic index (embeddings live next to the node
# index on the sealed volume; the drive is its own RAG store).
# python3 + libgl/libglib host the docling conversion sidecar (PDF /
# Office / images to markdown; libgl is an opencv runtime dependency).
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        postgresql-16-pgvector \
        python3 \
        python3-venv \
        libgl1 \
        libglib2.0-0 \
        tesseract-ocr \
        tesseract-ocr-eng \
    && rm -rf /var/lib/apt/lists/*

# Docling conversion sidecar (drive plan section 8.2): pinned version,
# CPU-only torch (the default wheels bundle CUDA), and the layout /
# table / OCR models BAKED INTO THE IMAGE at build time so conversion
# never downloads at runtime and stays part of the measured image.
RUN python3 -m venv /opt/docling-venv \
    && /opt/docling-venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/docling-venv/bin/pip install --no-cache-dir \
        torch torchvision --index-url https://download.pytorch.org/whl/cpu \
    && /opt/docling-venv/bin/pip install --no-cache-dir docling==2.113.0
RUN /opt/docling-venv/bin/python -c "\
from pathlib import Path; \
from docling.utils.model_downloader import download_models; \
download_models(output_dir=Path('/opt/docling-models'), progress=False)"
ENV DOCLING_ARTIFACTS_PATH=/opt/docling-models
COPY docling/server.py /opt/docling/server.py
# Import smoke test: a broken sidecar must fail the build, not the enclave.
RUN /opt/docling-venv/bin/python -c "import docling; import compileall, sys; sys.exit(0 if compileall.compile_file('/opt/docling/server.py', quiet=1) else 1)"

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
