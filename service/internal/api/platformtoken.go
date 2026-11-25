package api

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// isPlatformToken reports whether a JWT names a platform audience
// (privasys-platform, or privasys-platform-<env>), as a string or in an
// array. A platform sign-in token belongs to the platform and is never
// accepted by an app: the runtime strips it before the app, and Drive
// refuses one that reaches it any other way (a body field, a header). The
// payload is read without verification: the answer only refuses.
func isPlatformToken(tok string) bool {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return false
	}
	var claims struct {
		Aud json.RawMessage `json:"aud"`
	}
	if json.Unmarshal(raw, &claims) != nil || len(claims.Aud) == 0 {
		return false
	}
	var auds []string
	var one string
	if json.Unmarshal(claims.Aud, &one) == nil {
		auds = []string{one}
	} else if json.Unmarshal(claims.Aud, &auds) != nil {
		return false
	}
	for _, a := range auds {
		if a == "privasys-platform" || strings.HasPrefix(a, "privasys-platform-") {
			return true
		}
	}
	return false
}
