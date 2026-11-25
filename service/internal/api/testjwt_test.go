package api

import "encoding/base64"

// testJWT builds an unsigned JWT-shaped string with the given claims, for
// the checks that read claims without verifying (the vaults verify).
func testJWT(claims string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"ES256","typ":"JWT"}`)) + "." + enc([]byte(claims)) + ".sig"
}
