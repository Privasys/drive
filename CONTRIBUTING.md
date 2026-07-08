# Contributing

Thank you for your interest in Privasys Drive.

## Ground rules

- All commits MUST be GPG-signed. CI rejects unsigned commits on `main`.
- Pull requests require one approving review and a green CI before
  merge. Squash-merge is the default.
- Conventional Commits style for messages
  (`feat(service): add app-grant revocation endpoint`).
- AGPL-3.0: by contributing you license your work under the same
  terms.

## Development setup

Prerequisites:

- Go 1.25+
- Node 20+
- Postgres 17 (Docker is fine)
- A working `gpg` agent if you intend to push commits

Clone:

```bash
git clone git@github.com:Privasys/drive.git
cd drive
```

Run the test suite:

```bash
cd service && go test ./...
cd ../sdk && npm install && npm test
```

Run the service locally with an ephemeral SQLite store and a local-disk
object backend (no external dependencies needed):

```bash
cd service
go run ./cmd/drive serve --dev
```

## Testing

- Unit tests live next to the code (`*_test.go`, `*.test.ts`).
- Integration tests for the service live in
  `service/internal/storage/integration_test.go` and exercise both the
  SQLite and Postgres backends.
- Crypto invariants (round-trip, tamper-detection, Merkle-root
  stability) live in `service/internal/crypto/*_test.go` and MUST be
  kept exhaustive; these are the trust core.

## Reporting bugs

Open a [GitHub issue](https://github.com/Privasys/drive/issues). For
security bugs, see [SECURITY.md](SECURITY.md); please do not open
public issues for them.

## Code review checklist

- [ ] Tests added for new behaviour, regression test for fixed bugs.
- [ ] No new external dependencies without discussion.
- [ ] Public API additions documented in the relevant `README.md`.
- [ ] No secrets, credentials, or PII in fixtures or tests.
- [ ] Commits are GPG-signed.

## Release process

Tag a Conventional Commits release on `main`:

```bash
git tag -s vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z
```

The `release` workflow builds the reproducible image and publishes
it to `ghcr.io/privasys/drive:vX.Y.Z`.
