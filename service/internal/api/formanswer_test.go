package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Privasys/drive/service/internal/config"
	"github.com/Privasys/drive/service/internal/notify"
	"github.com/Privasys/drive/service/internal/oidc"
)

const formTestAppID = "02104572ca2f41e8ae2d24c0294e6f5e"

// A test IdP: discovery, a JWKS with one P-256 key, and a minter.
type testIdP struct {
	*httptest.Server
	key *ecdsa.PrivateKey
}

func newTestIdP(t *testing.T) *testIdP {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	idp := &testIdP{key: key}
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": idp.URL, "jwks_uri": idp.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "EC", "crv": "P-256", "kid": "k1", "alg": "ES256", "use": "sig",
			"x": b64(key.X.FillBytes(make([]byte, 32))), "y": b64(key.Y.FillBytes(make([]byte, 32))),
		}}})
	})
	idp.Server = httptest.NewServer(mux)
	t.Cleanup(idp.Close)
	return idp
}

func (idp *testIdP) mint(t *testing.T, header, claims map[string]any) string {
	t.Helper()
	h := map[string]any{"alg": "ES256", "kid": "k1", "typ": FormAnswerType}
	for k, v := range header {
		h[k] = v
	}
	hb, _ := json.Marshal(h)
	cb, _ := json.Marshal(claims)
	in := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	sum := sha256.Sum256([]byte(in))
	r, s, err := ecdsa.Sign(rand.Reader, idp.key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return in + "." + base64.RawURLEncoding.EncodeToString(sig)
}

type pushed struct {
	Sub     string         `json:"sub"`
	Type    string         `json:"type"`
	Payload map[string]any `json:"payload"`
}

// A sharer answers a share request in the wallet: only an answer token the
// IdP signed for this app, this form, this person and an offered action
// decides it, and only once.
func TestFormAnswer(t *testing.T) {
	ts, srv := newTestServer(t)
	idp := newTestIdP(t)

	pushes := make(chan pushed, 8)
	mgmt := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p pushed
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &p)
		pushes <- p
	}))
	t.Cleanup(mgmt.Close)
	srv.notifier = &notify.Client{BaseURL: mgmt.URL, HC: http.DefaultClient,
		Headers: func(context.Context) (string, string, string, error) { return "i", "c", "e", nil }}
	srv.InstallConfig(&config.Config{AppMessages: true})
	srv.FormAnswers = oidc.NewJWKSVerifier(idp.URL, FormAnswerAudience(formTestAppID)).WithType(FormAnswerType)
	next := func(typ string) pushed {
		t.Helper()
		select {
		case p := <-pushes:
			if p.Type != typ {
				t.Fatalf("push: want %s, got %+v", typ, p)
			}
			return p
		case <-time.After(5 * time.Second):
			t.Fatalf("no %s push", typ)
		}
		return pushed{}
	}

	const owner, recipient = "user-1", "user-2"
	tenantID, nodeID, payload := ownerTenantWithFile(t, ts.URL, owner)
	l := createLink(t, ts.URL, tenantID, nodeID, owner, `{"mode":"restricted","scope":["read"],"required_attributes":["name"]}`)
	code, b := doReq(t, bearerReq(t, "POST", fmt.Sprintf("%s/v1/links/%s/redeem", ts.URL, l["id"]), recipient,
		`{"secret":"`+l["secret"].(string)+`","attributes":{"name":"Test Person"}}`))
	if code != 200 {
		t.Fatalf("redeem: %d %s", code, b)
	}
	var rr struct {
		RequestID string `json:"request_id"`
	}
	_ = json.Unmarshal(b, &rr)

	p := next(appForm)
	form, _ := p.Payload["form"].(string)
	if p.Sub != owner || p.Payload["kind"] != "request" || !strings.Contains(form, `"id":"`+rr.RequestID+`"`) ||
		!strings.Contains(form, "Test Person") {
		t.Fatalf("form push: %+v", p)
	}

	good := map[string]any{
		"iss": idp.URL, "aud": FormAnswerAudience(formTestAppID), "sub": owner,
		"form_id": rr.RequestID, "form_digest": formDigest(form), "action": "approve",
		"jti": "j1", "exp": time.Now().Add(5 * time.Minute).Unix(),
	}
	with := func(k string, v any) map[string]any {
		c := map[string]any{}
		for kk, vv := range good {
			c[kk] = vv
		}
		c[k] = v
		return c
	}
	answer := func(token, action string) int {
		body, _ := json.Marshal(formAnswerRequest{FormID: rr.RequestID, Action: action, Answer: token})
		code, _ := doReq(t, mustReq(t, "POST", ts.URL+formAnswerPath, string(body)))
		return code
	}

	for name, c := range map[string]struct {
		token string
		want  int
	}{
		"wrong aud":    {idp.mint(t, nil, with("aud", "app-form:00000000-0000-0000-0000-000000000000")), http.StatusUnauthorized},
		"wrong typ":    {idp.mint(t, map[string]any{"typ": "JWT"}, good), http.StatusUnauthorized},
		"expired":      {idp.mint(t, nil, with("exp", time.Now().Add(-time.Minute).Unix())), http.StatusUnauthorized},
		"other form":   {idp.mint(t, nil, with("form_digest", formDigest(form+" "))), http.StatusForbidden},
		"someone else": {idp.mint(t, nil, with("sub", recipient)), http.StatusForbidden},
		"other action": {idp.mint(t, nil, with("action", "deny")), http.StatusForbidden},
	} {
		if got := answer(c.token, "approve"); got != c.want {
			t.Fatalf("%s: want %d, got %d", name, c.want, got)
		}
	}
	if code, _ := doReq(t, bearerReq(t, "GET", fmt.Sprintf("%s/v1/tenants/%s/files/%s", ts.URL, tenantID, nodeID), recipient, "")); code != http.StatusForbidden {
		t.Fatalf("a refused answer granted access: %d", code)
	}

	// The wallet's check that the form is Drive's own and still open.
	// Through the whole handler, as the runtime reaches it.
	full := httptest.NewServer(srv.Handler(""))
	t.Cleanup(full.Close)
	open := func(id, digest string) (int, []byte) {
		return doReq(t, mustReq(t, "GET", full.URL+"/.well-known/privasys/app-form?id="+id+"&digest="+digest, ""))
	}
	if code, b := open(rr.RequestID, formDigest(form)); code != 200 || !strings.Contains(string(b), `"open":true`) {
		t.Fatalf("open form: %d %s", code, b)
	}
	if code, _ := open("5b1e4c1a-0d6f-4b36-9a43-7d1f3b0c2e11", formDigest(form)); code != http.StatusNotFound {
		t.Fatalf("unknown id: want 404, got %d", code)
	}
	if code, _ := open(rr.RequestID, formDigest(form+" ")); code != http.StatusNotFound {
		t.Fatalf("wrong digest: want 404, got %d", code)
	}

	token := idp.mint(t, nil, good)
	if got := answer(token, "approve"); got != http.StatusOK {
		t.Fatalf("answer: want 200, got %d", got)
	}
	if r := next(appMessage); r.Sub != recipient || r.Payload["kind"] != "response" ||
		r.Payload["path"] != "/#shared/"+tenantID+"/"+nodeID {
		t.Fatalf("response push: %+v", r)
	}
	code, b = doReq(t, bearerReq(t, "GET", fmt.Sprintf("%s/v1/tenants/%s/files/%s", ts.URL, tenantID, nodeID), recipient, ""))
	if code != 200 || string(b) != string(payload) {
		t.Fatalf("approved read: %d", code)
	}

	if code, _ := open(rr.RequestID, formDigest(form)); code != http.StatusNotFound {
		t.Fatalf("answered form: want 404, got %d", code)
	}

	// Single use: the same answer again, or another one, is refused.
	if got := answer(token, "approve"); got != http.StatusConflict {
		t.Fatalf("replay: want 409, got %d", got)
	}
	if got := answer(idp.mint(t, nil, with("jti", "j2")), "approve"); got != http.StatusConflict {
		t.Fatalf("second answer: want 409, got %d", got)
	}

	// Off unless the instance turns app messages on.
	srv.InstallConfig(&config.Config{})
	if got := answer(token, "approve"); got != http.StatusNotFound {
		t.Fatalf("app messages off: want 404, got %d", got)
	}
}

func mustReq(t *testing.T, method, url, body string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	return req
}
