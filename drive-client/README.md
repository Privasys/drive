# `drive-client/`: `@privasys/drive-client`

The browser side of Privasys Drive's channel: the request carrier over
an `@privasys/auth` AppChannel (sealed or direct), chunked uploads, and the file-drop hook. The
Drive UI (`web/`) uses it from this directory; Privasys Chat pins the published
package.

Ships as TypeScript source. A Next.js consumer lists it in
`transpilePackages`.

## Publishing

Bump `version` in `package.json`, then push a signed tag
`drive-client-v<version>`. The `drive-client-publish` workflow publishes it to
GitHub Packages.
