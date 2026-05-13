# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Privasys Drive, please
report it privately. **Do not open a public GitHub issue.**

Email: **security@privasys.org**

PGP key: see https://privasys.org/.well-known/security.asc

We aim to acknowledge new reports within two business days and to
provide an initial assessment within five business days.

## Scope

In scope:

- The `service/` Go binary and its REST + MCP surfaces.
- The `sdk/` TypeScript client and its handling of cryptographic
  material.
- The `extraction/`, `render/`, and `web/` components once published.
- Reproducible build pipeline and container image integrity.

Out of scope:

- Vulnerabilities that require a malicious operator with full
  control of the host kernel: by design, the in-enclave components
  are deployed via dm-verity-protected confidential VMs and pinned
  by RA-TLS on the client side. See the
  [Privasys platform threat model](https://docs.privasys.org/security/).
- Bugs in third-party dependencies that are not exploitable through
  Privasys Drive's API surface.
- DoS at network or infrastructure level.

## Disclosure

We follow coordinated disclosure: we will work with you on a
timeline, credit you in the release notes (unless you prefer to
remain anonymous), and publish a CVE when appropriate.

## Cryptographic primitives

| Use | Algorithm |
|---|---|
| Chunk + manifest AEAD | XChaCha20-Poly1305 (256-bit key, 192-bit nonce) |
| Key derivation | HKDF-SHA-256 |
| Filename HMAC | HMAC-SHA-256 (32-byte tag, fixed length) |
| Merkle tree hash | SHA-256 |
| AppGrant token signature | Ed25519 |
| Transport | RA-TLS (TLS 1.3 + 0xFFBB attestation extension) |

If a primitive is broken or deprecated upstream, we will rotate via
a versioned key derivation label (`HKDF("privasys-drive/dek/v2", …)`)
and a coordinated re-encryption window.
